# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

###############################################################################
# Export-AADAssignments.ps1

# This script will identify all User-AppRole assignments for the specified
# application within Azure AD, and then output a matching set of AWS SSO
# Assignments as a CloudFormation template.

# NOTE: Add the relevant Users and PermissionSets must pre-exist within the
# target AWS SSO instance before the script is run.  If the required user
# or permission set for an assignment cannot be found, then the assignment
# will be ignored.
###############################################################################
[CmdletBinding()]
param (
    [Parameter(
        Mandatory = $true,
        HelpMessage = 'Object ID of the AzureAD Enterprize application to export roles from (required)'
    )]
    [string]$AppObjectId,

    [Parameter(
        Mandatory = $true,
        HelpMessage = 'ARN of the AWS SSO Instance assignments will be mapped into (required)'
    )]
    [string]$SSOInstanceArn,

    [Parameter(
        Mandatory = $true,
        HelpMessage = 'The ID of the directory used by AWS SSO (required)'
    )]
    [string]$IdentityStoreId,

    [Parameter(
        Mandatory = $true,
        HelpMessage = 'The id of the AWS region where AWS SSO is deployed (required)'
    )]
    [string]$AWSRegion,

    [Parameter(
        HelpMessage = 'File path to write output (default .\assignments.json)'
    )]
    [string]$OutputFilePath = '.\assignments.json'
)

# Turn on logging at Info level
$InformationPreference = 'Continue'

###############################################################################
# Get all of the user-role assignments for the target Azure AD application
# Assignments are a mapping between an Azure AD user or group, and an application role.
# When the target application is AWS, then the AppRoles map to AWS IAM Roles.
function GetAADAssignments {
    # Get the raw assignments from Azure AD
    $rawAssignments = Get-AzureADServiceAppRoleAssignment -ObjectId $AppObjectId

    $assignments = New-Object -TypeName System.Collections.Arraylist

    foreach ($rawAssignment in $rawAssignments) {
        $assignment = @{
            Type      = $rawAssignment.PrincipalType
            AppRoleId = $rawAssignment.Id
        }

        if ($rawAssignment.PrincipalType -eq 'User') {
            # Have to look up the user to get their Username (email) rather than DisplayName
            $user = Get-AzureADUser -ObjectId $rawAssignment.PrincipalId
            $assignment['Name'] = $User.UserPrincipalName
        } elseif ($rawAssignment.PrincipalType -eq 'Group') {
            $assignment['Name'] = $rawAssignment.PrincipalDisplayName
        } else {
            continue
        }

        $assignments.Add($assignment) | Out-Null
    }

    return , $assignments
}

###############################################################################
# Builds a Map of the Azure AD Application Roles for the target application
#
# The the target application should represent an AWS Organization, and therefor
# these App Roles should map to an AWS IAM Role
function GetAADRoles {
    # Get the App Registration record from Azure AD
    $app = Get-AzureADServicePrincipal -ObjectId $AppObjectId

    # Create a Hashtable of AppRoles so that we can look them up quickly later
    $rolesMap = @{}

    foreach ($role in $app.AppRoles) {
        if ($null -eq $role.Value) {
            continue
        }

        # Find the ARN of the IAM Role within the value
        $pattern = 'arn:aws:iam::(\d{12}):role/(.+?)(,|$)'
        if ($role.Value -match $pattern) {
            # Save account id and role name into the map
            $rolesMap[$role.Id] = @{
                Account = $Matches[1]
                Name    = $Matches[2]
            }
        } else {
            Write-Warning "Ignoring AppRole due to no IAM Role ARN within AppRole value [Id: $($role.Id), Name: $($role.DisplayName), Value: $($role.Value)]"
        }
    }

    return $rolesMap
}

###############################################################################
# Get the set of Permission Sets available within the target AWS SSO instance
function GetAWSPermissionSets {
    $arnList = Get-SSOADMNPermissionSetList -InstanceArn $SSOInstanceArn -Region $AWSRegion
    $permissionSets = @{}

    # Loop over the list to turn the list of ARNs into the actual permission set objects
    foreach ($permissionSetArn in $arnList) {
        $permissionSet = Get-SSOADMNPermissionSet -InstanceArn $SSOInstanceArn -PermissionSetArn $permissionSetArn -Region $AWSRegion
        $permissionSets[$permissionSet.Name] = $permissionSet
    }

    return $permissionSets
}

function GetPermissionSetForAppRole {
    param (
        [string]$Name,
        [string]$Account,
        [Hashtable]$PermissionSets
    )

    # First look for an Account specific Permission Set
    $permissionSet = $PermissionSets["$Account - $Name"]
    if ($null -ne $permissionSet) {
        return $permissionSet
    }

    # Second look for a generic permisison set which matches the role name
    $permissionSet = $PermissionSets[$Name]
    if ($null -ne $permissionSet) {
        return $permissionSet
    }

    # Failed to find a matching permission set, return null
    return $null
}

###############################################################################
# Get the AWS SSO internal ID for a specified user
# This ID is required when we come to create user-permissionset assignments in AWS SSO
$_userCache = @{}
function GetUserID {
    param (
        [string]$UserName
    )
    Write-Debug "Getting user id for $UserName"

    if ($null -ne $_userCache[$UserName]) {
        Write-Debug 'Found user in cache'
        return $_userCache[$UserName]
    }

    $user = Find-IDSUserList -IdentityStoreId $IdentityStoreId -Filter @(@{AttributePath = 'UserName'; AttributeValue = $UserName }) -Region $AWSRegion

    if ($null -ne $user) {
        Write-Debug 'Retrieved user from AWS identity store'
        $_userCache[$UserName] = $user.UserId
        return $user.UserId
    }

    Write-Warning "Failed to find user ($UserName) in AWS SSO"
    return $null
}


###############################################################################
# Get the AWS SSO internal ID for a specified group
# This ID is required when we come to create user-permissionset assignments in AWS SSO
$_groupCache = @{}
function GetGroupID {
    param (
        [string]$GroupName
    )
    Write-Debug "Getting group id for $GroupName"

    if ($null -ne $_groupCache[$GroupName] ) {
        Write-Debug 'Found group in cache'
        return $_groupCache[$GroupName]
    }

    $group = Find-IDSGroupList -IdentityStoreId $IdentityStoreId -Filter @(@{AttributePath = 'DisplayName'; AttributeValue = $GroupName }) -Region $AWSRegion

    if ($null -ne $group) {
        Write-Debug 'Retrieved group from AWS identity store'
        $_groupCache[$GroupName] = $group.GroupId
    } else {
        Write-Warning "Failed to find group ($GroupName) in AWS SSO"
    }
}


###############################################################################
# Generate a CloudFormation representation of the Assignments that existed
# within the Azure AD application
function OutputAssignmentsToCFN {
    param (
        $AADAssignments,
        $AADRoles,
        $SSOPermissionSets
    )
    $cfn = @{
        AWSTemplateFormatVersion = '2010-09-09'
        Description              = 'Template for importing existing Federated IAM Roles into AWS SSO Permission Sets'
        Resources                = @{}
    }
    $resources = $cfn['Resources']

    $idx = 0
    foreach ($assignment in $AADAssignments) {

        $role = $AADRoles[$assignment['AppRoleId']]
        if ($null -eq $role) {
            Write-Warning "Assignment skipped due to missing AppRole in Azure AD [AppRoleId: $($assignment['AppRoleId'])]"
            continue
        }

        $permissionSet = GetPermissionSetForAppRole -Name $role['Name'] -Account $role['Account'] -PermissionSets $SSOPermissionSets
        if ($null -eq $permissionSet) {
            Write-Warning "Assignment skipped due to no matching PermissionSet in AWS SSO [Role/PermissionSet Name: $($role['Name']), Account: $($role['Account'])]"
            continue
        }

        # Begin building CloudFormation resource definition
        # Type: AWS::SSO::Assignment
        # Properties:
        #   InstanceArn: String
        #   PermissionSetArn: String
        #   PrincipalType: String
        #   PrincipalId: String
        #   TargetType: String
        #   TargetId: String

        $ssoAssignment = @{
            Type       = 'AWS::SSO::Assignment'
            Properties = @{
                InstanceArn      = $SSOInstanceArn
                PermissionSetArn = $permissionSet.PermissionSetArn
                TargetType       = 'AWS_ACCOUNT'
                TargetId         = $role['Account']
            }
        }
        $properties = $ssoAssignment.Properties

        if ($assignment['Type'] -eq 'User') {
            $user = GetUserID -UserName $assignment['Name']
            if ($null -eq $user) {
                Write-Warning "Assignment skipped due to no matching user in AWS SSO [User: $($assignment['Name'])]"
                continue
            }

            $properties['PrincipalType'] = 'USER'
            $properties['PrincipalId'] = $user

        } elseif ($assignment['Type'] -eq 'Group') {
            $group = GetGroupID $assignment['Name']
            if ($null -eq $group) {
                Write-Warning "Assignment skipped due to no matching group in AWS SSO [Group: $($assignment['Name'])]"
                continue
            }

            $properties['PrincipalType'] = 'GROUP'
            $properties['PrincipalId'] = $group

        } else {
            Write-Warning "Assignment skipped due to unknown principal type [Type: $($assignment['Type']), Identifier: $($assignment['Name'])]"
            continue
        }

        # Can't use user/group + role name as the Logical ID as role names allow special chars
        $resources['Assignment' + $idx++] = $ssoAssignment

        if (0 -eq (($idx + 1) % 10) ) {
            Write-Information "Processed $idx assignments"
        }
    }

    return ConvertTo-Json -InputObject $cfn -Depth 10 | Format-Json
}

# Formats JSON in a nicer format than the built-in ConvertTo-Json does
function Format-Json {
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [String] $Json
    )
    $indent = 0
    ($Json -Split "`n" | ForEach-Object {
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

$aadAssignments = GetAADAssignments
$aadRoles = GetAADRoles
Write-Information "Found $($aadRoles.Count) Roles and $($aadAssignments.Count) Assignments within the Azure AD application"

$ssoPermissionSets = GetAWSPermissionSets
Write-Information "Found $($ssoPermissionSets.Count) PermissionSets within AWS Single Sign-On"

Write-Information 'Beginning export of Assignments into CloudFormation'
$cfn = OutputAssignmentsToCFN -AADAssignments $aadAssignments -AADRoles $aadRoles -SSOPermissionSets $ssoPermissionSets
Write-Debug "Generated CloudFormation\n$cfn"

# Save CloudFormation to a file
$cfn | Out-File -Encoding 'utf8' -FilePath $OutputFilePath
Write-Information "Successfully wrote file $OutputFilePath"
