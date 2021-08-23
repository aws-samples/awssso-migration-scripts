# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

###############################################################################
# Export-IAMSAMLRoles.ps1
#
# This script will recursively scan all accounts in an AWS Organization looking
# for IAM Roles that have a trust policy referring to the specified SAML IDP.
# Identified roles are deduplicated and converted into a matching set of
# AWS SSO PermissionSets. These PermissionSets are then output as a
# CloudFormation template
###############################################################################
param (
    [Parameter(
        Mandatory = $true,
        HelpMessage = 'Entity Descritor ID from SAML Manifest which represents the existing Identity Provider (required)'
    )]
    [string]$EntityDescriptorID,

    [Parameter(
        HelpMessage = 'AWS IAM Role that can be assumed to read the roles within each child account (default AWS_IAM_AAD_UpdateTask_CrossAccountRole). This role must pre-exist'
    )]
    [string]$CrossAccountRole = 'AWS_IAM_AAD_UpdateTask_CrossAccountRole',

    [Parameter(
        HelpMessage = 'File path to write output (default .\permission-sets.json)'
    )]
    [string]$OutputFilePath = '.\permission-sets.json'
)

# Turn on logging at Info level
$InformationPreference = 'Continue'

# Include system.web for URLDecode utility
Add-Type -AssemblyName System.Web

###############################################################################
# Recursively check each child account within the AWS organization to
# identify any existing IAM Roles that have a trust policy pointing to
# the specified SAML IDP
function GetOrganizationRoles {
    Write-Information 'Confirming access into AWS accounts within the Organization'

    $rootAccount = (Get-STSCallerIdentity).Account
    $childAccounts = Get-ORGAccountList
    $credList = New-Object -TypeName System.Collections.ArrayList

    Write-Information "Found $($childAccounts.Count) child account(s)"

    # Built a list of account credentials we can come back to use later
    Foreach ($childAccount in $childAccounts) {
        if ($childAccount.Status -ne 'ACTIVE' -OR $childAccount.Id -eq $RootAccount) {
            continue
        }

        # Skip over accounts we can't access
        try {
            $creds = (Use-STSRole -RoleArn "arn:aws:iam::$($childAccount.Id):role/$($CrossAccountRole)" -RoleSessionName 'AWS_SSO_Migration').Credentials
            $account = @{
                Id          = $childAccount.Id
                Credentials = $creds
            }
            $credList.Add($account) | Out-Null
            Write-Information "Account $($childAccount.Id): Confirmed access into role '$($CrossAccountRole)'"
        } catch {
            Write-Warning "Account $($childAccount.Id): Could not assume role '$($CrossAccountRole)'. Skipping..."
        }
    }

    $roles = New-Object -TypeName System.Collections.Arraylist

    Write-Debug "Getting Roles for $rootAccount (Org root)"
    $tmp = GetCurrentAccountRoles -AccountID $rootAccount # Get roles for payer account
    Write-Information "Account $($rootAccount): Found $($tmp.Count) roles within account"
    if ($tmp.Count -gt 0) {
        $roles.AddRange($tmp) | Out-Null
    }

    foreach ($account in $credList) {
        Write-Debug "Getting Roles for $($account.Id)"
        Set-AWSCredential -Credential $account.Credentials # Set default credentials to the next child account
        $tmp = GetCurrentAccountRoles -AccountID $account.Id # Get roles for Child account

        Write-Information "Account $($account.Id): Found $($tmp.Count) roles within account"
        if ($tmp.Count -gt 0) {
            $roles.AddRange($tmp) | Out-Null
        }
    }

    return , $roles
}


###############################################################################
# Get the IAM Roles for the currently authenticated AWS Account
function GetCurrentAccountRoles {
    param (
        [string]$AccountID
    )
    $roles = New-Object -TypeName System.Collections.Arraylist
    $idpARNs = FindSAMLProviderArn

    if (1 -gt $idpARNs.Count) {
        Write-Warning "Account $($AccountID): No SAML IDP matching $EntityDescriptorID. Skipping..."
        return $roles
    }

    foreach ($idpARN in $idpARNs) {
        if (-not([string]::IsNullOrWhiteSpace($idpARN))) {
            $tmp = FindFederatedRoles -IDPARN $idpARN
            $roles.AddRange($tmp) | Out-Null
        }
    }

    return , $roles
}

###############################################################################
# Get the ARN of any IAM IDPs that reference the target SAML IDP
# There will typically be only one within an account
function FindSAMLProviderArn {
    $idpARNs = New-Object -TypeName System.Collections.Arraylist
    Write-Debug "Looking for $EntityDescriptorID within IAM SAML IDPs"

    $samlProviders = Get-IAMSAMLProviderList
    foreach ($provider in $samlProviders) {
        $detail = Get-IAMSAMLProvider -SAMLProviderArn $provider.Arn

        $metadata = [xml]$detail.SAMLMetadataDocument

        Write-Debug "Metadata is $($metadata.InnerXml)"
        Write-Debug "Found $($metadata.EntityDescriptor.ID)"

        if ($metadata.EntityDescriptor.ID -eq $EntityDescriptorID) {
            Write-Debug "Found IDP $($provider.Arn)"
            $idpARNs.Add($provider.Arn) | Out-Null
        }
    }

    return , $idpARNs
}

###############################################################################
# Get all IAM Roles that have a trust policy targeting the specified IDP
function FindFederatedRoles {
    param (
        [string]$IDPARN
    )
    $roles = New-Object -TypeName System.Collections.Arraylist

    $iamRoleList = Get-IAMRoleList

    foreach ($iamRole in $iamRoleList) {
        if ($iamRole.AssumeRolePolicyDocument -like "*SAML*") {
            $document = [System.Net.WebUtility]::UrlDecode($iamRole.AssumeRolePolicyDocument)
            $expected = '*{0}*' -f $IDPARN

            Write-Debug "Looking for $IDPARN in role trust policy: $document"

            if ($document -like $expected) {
                $roleHash = @{
                    Arn             = $iamRole.Arn
                    RoleName        = $iamRole.RoleName
                    Description     = $iamRole.Description
                    SessionDuration = $iamRole.MaxSessionDuration
                    Account         = GetAccountFromArn -RoleArn $iamRole.Arn
                }
                $role = FindRolePolicies -RoleHash $roleHash

                # Role will be null if we were unable to correctly merge the role's policy documents
                if ($null -ne $role) {
                    $roles.Add($role) | Out-Null
                }
            }
        }
    }

    return , $roles
}

function GetAccountFromArn {
    param (
        [string]$RoleArn
    )
    $pattern = 'arn:aws:iam::(\d{12}):role/.+'
    if ($RoleArn -match $pattern) {
        return $Matches[1]
    } else {
        return $null
    }
}

###############################################################################
# Get the IAM Policies (both inline and managed) that are attached to the
# specified IAM Role.
#
# Where there are multiple custom policies, these will be
# merged into the single inline policy document as required by AWS SSO
# Permission Sets.  If this results in a policy which overflows the character
# limit then the role is skipped (and a Permission Set will not be created)
function FindRolePolicies {
    param (
        [Hashtable]$RoleHash
    )

    $policies = New-Object -TypeName System.Collections.Arraylist
    $documents = New-Object -TypeName System.Collections.Arraylist

    # Inline policies
    $policyList = Get-IAMRolePolicyList -RoleName $RoleHash['RoleName']
    Write-Debug "$($RoleHash['RoleName']): Found $($policyList.Count) inline policies on role"
    foreach ($name in $policyList) {
        $policy = Get-IAMRolePolicy -RoleName $RoleHash['RoleName'] -PolicyName $name
        $document = [System.Web.HttpUtility]::UrlDecode($policy.PolicyDocument)
        $document = ConvertFrom-Json -InputObject $document
        $documents.Add($document) | Out-Null
    }

    # Managed policies
    $attachedPolicyList = Get-IAMAttachedRolePolicyList -RoleName $RoleHash['RoleName']
    Write-Debug "$($RoleHash['RoleName']): Found $($attachedPolicyList.Count) attached policies on role"
    foreach ($attachedPolicy in $attachedPolicyList) {
        if ($attachedPolicy.PolicyArn.StartsWith('arn:aws:iam::aws:policy/')) {
            # This is an AWS Managed Policy
            $policies.Add($attachedPolicy.PolicyArn) | Out-Null
        } else {
            # This is a Customer Managed Policy
            $policy = Get-IAMPolicy -PolicyArn $attachedPolicy.PolicyArn
            $version = Get-IAMPolicyVersion -PolicyArn $attachedPolicy.PolicyArn -VersionId $Policy.DefaultVersionId

            $document = [System.Web.HttpUtility]::UrlDecode($version.Document)
            $document = ConvertFrom-Json -InputObject $document
            $documents.Add($document) | Out-Null
        }
    }

    $RoleHash['Policies'] = $policies.ToArray()

    if ($documents.Count -eq 1) {
        $RoleHash['Document'] = $documents[0]
    } elseif ($documents.Count -gt 1) {
        Write-Debug "$($RoleHash['RoleName']): Found $($documents.Count) total customer policies on role. Will merge these into a single policy"

        $statements = New-Object -TypeName System.Collections.ArrayList

        # Merge custom policy documents as SSO Permission Sets only support a single inline policy
        foreach ($document in $documents) {
            foreach ($statement in $document.Statement) {
                # Sid values are optional, but need to be unique within a policy document
                # TODO Future Improvement - keep Sid values, but update them to avoid conflicts
                $statement.PSObject.Properties.Remove('Sid')

                $statements.Add($statement) | Out-Null
            }
        }
        $mergedDoc = @{
            Version   = '2012-10-17'
            Statement = $statements.ToArray()
        }

        # Check if the resulting policy document will fit within a SSO Permission Set's inline policy (10240 characters)
        $policyString = ConvertTo-Json -InputObject $mergedDoc -Depth 10
        if ($policyString.Length -gt 10240) {
            Write-Warning "Unable to creation Permission Set for $($RoleHash['RoleName']) as inline policies exceed 10240 characters when merged"
            return $null
        }

        Write-Debug "$($RoleHash['RoleName']): Resulting policy was: $policyString"

        $RoleHash['Document'] = $mergedDoc
    }

    return $RoleHash
}

###############################################################################
# Deduplicate roles based on whether their names and policies match
# E.g. Within an AWS Org there are likely to be several Admin roles across
# each of the child accounts. These can be represented as a single
# PermissionSet in AWS SSO
function DeduplicateRoles {
    param (
        [Hashtable[]]$Roles
    )
    $returnList = New-Object -TypeName System.Collections.Arraylist

    foreach ($role in $Roles) {
        $isNew = $true
        foreach ($roleBeingReturned in $returnList) {
            if (RolesMatch -Role1 $role -Role2 $roleBeingReturned) {
                $roleBeingReturned['Duplicate'] = $true
                $isNew = $false
                break
            }
        }

        # TODO check for role name clashes

        if ($isNew) {
            $returnList.Add($role) | Out-Null
        }
    }

    return $returnList
}

###############################################################################
# Compare roles - returns True if name and policies match exactly
function RolesMatch {
    param (
        [Hashtable]$Role1,
        [Hashtable]$Role2
    )

    if ($Role1['RoleName'] -ne $Role2['RoleName']) {
        return $false
    }

    $policyDiffs = Compare-Object -ReferenceObject $Role1['Policies'] -DifferenceObject $Role2['Policies']
    if ($policyDiffs.Length -gt 0) {
        return $false
    }

    $d1 = $Role1['Document']
    $d2 = $Role2['Document']
    if ($null -eq $d1 -and $null -eq $d2) {
        return $true
    } elseif ($null -ne $d1 -and $null -eq $d2) {
        return $false
    } elseif ($null -eq $d1 -and $null -ne $d2) {
        return $false
    } else {
        $docDiffs = Compare-Object -ReferenceObject $d1.PSObject.Properties -DifferenceObject $d2.PSObject.Properties
        if ($docDiffs.Length -gt 0) {
            return $false
        }
    }

    return $true
}

###############################################################################
# Generate a CloudFormation representation of AWS SSO PermissionSets
# that matches the existing IAM Roles identitied within the AWS Organization
function OutputRolesToCFN {
    param (
        [Hashtable[]]$Roles
    )

    $cfn = @{
        AWSTemplateFormatVersion = '2010-09-09'
        Description              = 'Template for importing existing Federated IAM Roles into AWS SSO Permission Sets'
        Parameters               = @{
            SSOInstanceARN = @{
                Type        = 'String'
                Description = 'The ARN of your AWS SSO Instance'
            }
        }
        Resources                = @{}
    }
    $resources = $cfn['Resources']

    # Type: AWS::SSO::PermissionSet
    # Properties:
    #   Description: String
    #   InlinePolicy: String
    #   InstanceArn: String
    #   ManagedPolicies:
    #       - String
    #   Name: String
    #   RelayStateType: String
    #   SessionDuration: String

    $idx = 0
    foreach ($role in $Roles) {
        $permissionSet = @{
            Type       = 'AWS::SSO::PermissionSet'
            Properties = @{
                InstanceArn     = @{
                    Ref = 'SSOInstanceARN'
                }
                Description     = $role['Description']
                SessionDuration = "PT$($role['SessionDuration'])S"
            }
        }
        $properties = $permissionSet.Properties

        # Specify the PermissionSet name
        if ($role['Duplicate']) {
            $properties['Name'] = $role['RoleName']
        } else {
            # Use account specific name to ensure non-shared roles are unique
            $properties['Name'] = "$($role['Account'])-$($role['RoleName'])"
        }

        if ($null -ne $role['Policies'] -AND $role['Policies'].Count -gt 0) {
            $properties['ManagedPolicies'] = $role['Policies']
        }
        if ($null -ne $role['Document']) {
            $properties['InlinePolicy'] = $role['Document']
        }

        # Can't use role name as the Logical ID as role names allow special chars
        $resources['PermissionSet' + $idx++] = $permissionSet
    }

    return ConvertTo-Json -InputObject $cfn -Depth 10 | Format-Json
}

# Formats JSON in a nicer format than the built-in ConvertTo-Json does
function Format-Json {
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [String]$json
    )
    $indent = 0;
    ($json -Split "`n" | ForEach-Object {
            if ($_ -match '[\}\]]\s*,?\s*$') {
                # This line ends with ] or }, decrement the indentation level
                $indent--
            }
            $line = ('  ' * $indent) + $($_.TrimStart() -replace '":  (["{[])', '": $1' -replace ':  ', ': ')
            if ($_ -match '[\{\[]\s*$') {
                # This line ends with [ or {, increment the indentation level
                $indent++
            }
            $line
        }) -Join "`n"
}

###############################################################################
# MAIN
###############################################################################

$roles = GetOrganizationRoles

# We now have all the roles from the Organization, but there are probably
# lots of duplicates due to the same role name existing in multiple accounts
$totalRoles = $roles.Count
$roles = DeduplicateRoles -Roles $roles
Write-Information "Found $totalRoles roles within the organization, which resulted in $($roles.Count) roles after deduplication"

$cfn = OutputRolesToCFN -Roles $roles
Write-Debug "Generated CloudFormation\n$cfn"

# Save CloudFormation to a file
$cfn | Out-File -Encoding 'utf8' -FilePath $OutputFilePath
Write-Information "Successfully wrote file $OutputFilePath"
