/*
   Begin common prolog commands
   export name=CrewTaskMgr
   export rg=rg_${name}
   export uniqueName=jac3sukjdrxzi
   export loc=westus
   End common prolog commands

   emacs F10
   Begin commands to deploy this file using Azure CLI with bash
   #echo WaitForBuildComplete
   WaitForBuildComplete
   #echo "begin shutdown"
   #az deployment group create --mode complete --template-file ./clear-resources.json --resource-group $rg
   echo az functionapp delete --name jac3sukjdrxzi-func-CrewTaskMgrAuthSvcs --resource-group $rg
   az functionapp delete --name jac3sukjdrxzi-func-CrewTaskMgrAuthSvcs --resource-group $rg
   echo az storage account delete -n ${uniqueName}stgctmfunc -g $rg --yes
   az storage account delete -n ${uniqueName}stgctmfunc -g $rg --yes
   echo az apim delete --name ${uniqueName}-apim  --resource-group $rg --yes
   az apim delete --name ${uniqueName}-apim  --resource-group $rg --yes
   echo az apim deletedservice purge --service-name ${uniqueName}-apim --location $loc
   az apim deletedservice purge --service-name ${uniqueName}-apim --location $loc
   echo Previous shutdown/build is complete. Begin deployment build.
   echo az deployment group create --name $name --resource-group $rg  --mode  Incremental  --template-file deploy-CrewTaskMgr.bicep  --parameters ownerId=$AZURE_OBJECTID  '@deploy.parameters.json' 
   az deployment group create --name $name --resource-group $rg  --mode  Incremental  --template-file deploy-CrewTaskMgr.bicep  --parameters ownerId=$AZURE_OBJECTID  '@deploy.parameters.json' 
   az resource list -g $rg --query "[?resourceGroup=='$rg'].{ name: name, flavor: kind, resourceType: type, region: location }" --output table
   End commands to deploy this file using Azure CLI with bash

   emacs ESC 2 F10
   Begin commands to shut down this deployment using Azure CLI with bash
   echo CreateBuildEvent.exe
   CreateBuildEvent.exe&
   echo "begin shutdown"
   az deployment group create --mode complete --template-file ./clear-resources.json --resource-group $rg
   #echo az group delete -g $rg  --yes 
   #az group delete -g $rg  --yes
   echo az keyvault purge --name ${uniqueName}-kv --location $loc --no-wait
   az keyvault purge --name ${uniqueName}-kv --location $loc --no-wait
   BuildIsComplete.exe
   az resource list -g $rg --query "[?resourceGroup=='$rg'].{ name: name, flavor: kind, resourceType: type, region: location }" --output table
   echo "showdown is complete"
   End commands to shut down this deployment using Azure CLI with bash

   emacs ESC 3 F10
   Begin commands for one time initializations using Azure CLI with bash
   az group create -l $loc -n $rg
   export id=`az group show --name $rg --query 'id' --output tsv`
   echo "id=$id"
   #export sp="spad_$name"
   #az ad sp create-for-rbac --name $sp --sdk-auth --role contributor --scopes $id
   #echo "go to github settings->secrets and create a secret called AZURE_CREDENTIALS with the above output"
   if [[ -e clear-resources.json ]]
   then
   echo clear-resources.json already exists
   else
   cat >clear-resources.json <<EOF
   {
    "\$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
     "contentVersion": "1.0.0.0",
     "resources": [] 
   }
   EOF
   fi
   End commands for one time initializations using Azure CLI with bash

   emacs ESC 4 F10
   Begin commands for one time initializations using Azure CLI with bash
   echo az apim  list --resource-group $rg 
   az apim list --resource-group $rg 
   echo az apim deletedservice list
   az apim deletedservice list
   End commands for one time initializations using Azure CLI with bash

   emacs ESC 5 F10
   Begin commands for one time initializations using Azure CLI with bash
   echo az apim delete --name ${uniqueName}-apim  --resource-group $rg --yes
   az apim delete --name ${uniqueName}-apim  --resource-group $rg --yes
   echo az apim deletedservice purge --service-name ${uniqueName}-apim --location $loc
   az apim deletedservice purge --service-name ${uniqueName}-apim --location $loc
   End commands for one time initializations using Azure CLI with bash

   emacs ESC 6 F10
   Begin commands for one time initializations using Azure CLI with bash
   echo az functionapp delete --name jac3sukjdrxzi-func-CrewTaskMgrAuthSvcs --resource-group $rg
   az functionapp delete --name jac3sukjdrxzi-func-CrewTaskMgrAuthSvcs --resource-group $rg
   End commands for one time initializations using Azure CLI with bash


 */
@description('Rquire Azure AD authentication for Azure Func CrewTaskMgrAuthSvs')
param requireAuthentication bool = true

param applicationId string

param location string = resourceGroup().location
param name string = uniqueString(resourceGroup().id)
@description('The App Configuration SKU. Only "standard" supports customer-managed keys from Key Vault')
@allowed([
    'free'
    'standard'
])
param configSku string = 'free'

@description('The web site hosting plan')
@allowed([
    'F1'
    'D1'
    'B1'
    'B2'
    'B3'
    'S1'
    'S2'
    'S3'
    'P1'
    'P2'
    'P3'
    'P4'
])
param webPlanSku string = 'F1'

param funcCrewTaskMgrAuthSvcsName string = 'CrewTaskMgrAuthSvcs'

@description('Azure AD B2C App Registration client secret')
@secure()
param BackEndClientSecret string

@description('Azure AD B2C Configuration [{key:"", value:""}]')
param aadb2cConfig object
@description('Hello Azure Function Configuration [{key:"", value:""}]')
param helloConfig object
@description('AAD Object ID of the developer so s/he can access key vault when running on development/deskop computer')
param ownerId string

@secure()
param ApplicationInsights_ConnectionString string

resource config 'Microsoft.AppConfiguration/configurationStores@2020-06-01' = {
    name: '${name}-config'
    location: location
    sku: {
        name: configSku
    }
    resource Aadb2cConfigValues 'keyValues@2020-07-01-preview' = [for item in items(aadb2cConfig): {
        name: 'AzureAdB2C:${item.key}'
        properties: {
            value: item.value
        }
    }]
    resource HelloConfigValues 'keyValues@2020-07-01-preview' = [for item in items(helloConfig): {
        name: 'Hello:${item.key}'
        properties: {
            value: item.value
        }
    }]
    resource aadb2cClientSecret 'keyValues@2020-07-01-preview' = {
        // Store secrets in Key Vault with a reference to them in App Configuration e.g., client secrets, connection strings, etc.
        name: 'AzureAdB2C:ClientSecret'
        properties: {
            // Most often you will want to reference a secret without the version so the current value is always retrieved.
            contentType: 'application/vnd.microsoft.appconfig.keyvaultref+json;charset=utf-8'
            value: '{"uri":"${kvaadb2cSecret.properties.secretUri}"}'
        }
    }
}
output MYSQLCONNSTR_AppConfig string = listKeys(config.id, config.apiVersion).value[0].connectionString

resource kv 'Microsoft.KeyVault/vaults@2019-09-01' = {
    // Make sure the Key Vault name begins with a letter.
    name: '${name}-kv'
    location: location
    properties: {
        sku: {
            family: 'A'
            name: 'standard'
        }
        tenantId: subscription().tenantId
        accessPolicies: [
            {
                tenantId: subscription().tenantId
                objectId: ownerId
                permissions: {
                    secrets: [
                        'all'
                    ]
                }
            }
            {
                tenantId: subscription().tenantId
                objectId: website.identity.principalId
                permissions: {
                    // Secrets are referenced by and enumerated in App Configuration so 'list' is not necessary.
                    secrets: [
                        'get'
                    ]
                }
            }
        ]
    }
}
resource kvaadb2cSecret 'Microsoft.KeyVault/vaults/secrets@2019-09-01' = {
    name: '${kv.name}/AzureAdB2CClientSecret'
    properties: {
        value: BackEndClientSecret
    }
}

@description('Cosmos DB account name (must contain only lowercase letters, digits, and hyphens)')
@minLength(3)
@maxLength(44)
param cosmosAccountName string = 'gpdocumentdb'

@secure()
param cosmosAccountKey string

@secure()
param cosmosEndPoint string

param hostingPlanName string = '${name}-plan'

output AccountKey string = cosmosAccountKey
output EndPoint string = cosmosEndPoint

resource webHostingPlan 'Microsoft.Web/serverfarms@2020-12-01' = {
    name: '${name}-web-plan'
    location: location
    sku: {
        name: 'F1'
        tier: 'Free'
        size: 'F1'
        family: 'F'
        capacity: 0
    }
    kind: 'app'
    properties: {
        perSiteScaling: false
        maximumElasticWorkerCount: 1
        isSpot: false
        reserved: false
        isXenon: false
        hyperV: false
        targetWorkerCount: 0
        targetWorkerSizeId: 0
    }
}

resource website 'Microsoft.Web/sites@2022-09-01' = {
    name: '${name}-web'
    location: location
    tags: {
        'hidden-related:/subscriptions/acc26051-92a5-4ed1-a226-64a187bc27db/resourceGroups/rg_CrewTaskMgr/providers/Microsoft.Web/serverFarms/CTMBlazorSvrClient20230409134317Plan': 'empty'
    }
    kind: 'app'
    identity: {
        type: 'SystemAssigned'
    }
    properties: {
        enabled: true
        hostNameSslStates: [
            {
                name: 'ctmblazorsvrclient20230409134317.azurewebsites.net'
                sslState: 'Disabled'
                hostType: 'Standard'
            }
            {
                name: 'ctmblazorsvrclient20230409134317.scm.azurewebsites.net'
                sslState: 'Disabled'
                hostType: 'Repository'
            }
        ]
        serverFarmId: webHostingPlan.id
        reserved: false
        isXenon: false
        hyperV: false
        vnetRouteAllEnabled: false
        vnetImagePullEnabled: false
        vnetContentShareEnabled: false
        siteConfig: {
            numberOfWorkers: 1
            acrUseManagedIdentityCreds: false
            alwaysOn: false
            http20Enabled: false
            functionAppScaleLimit: 0
            minimumElasticInstanceCount: 0
            appSettings: [// https://github.com/Azure/azure-quickstart-templates/blob/master/quickstarts/microsoft.web/documentdb-webapp/main.bicep
                {
                    name: 'COSMOS_GP_ENDPOINT'
                    value: cosmosEndPoint
                }
                {
                    name: 'COSMOS_GP_ACCOUNTKEY'
                    value: cosmosAccountKey
                }
                {
                    name: 'ASPNETCORE_ENVIRONMENT'
                    value: 'Development'
                }
                {
                    name: 'Logging:ApplicationInsights:Enabled'
                    value: 'true'
                }
                {
                    name: 'Logging:ApplicationInsights:LogLevel'
                    value: 'Trace'
                }
                {
                    name: 'Logging:LogLevel:Default'
                    value: 'Trace'
                }
                {
                    name: 'Logging.LogLevel:Microsoft'
                    value: 'Trace'
                }
                {
                    name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
                    value: ApplicationInsights_ConnectionString
                }
            ]
            //linuxFxVersion: 'DOCKER|siegfried01/blazorserverclient:latest'
            //linuxFxVersion: 'DOTNETCORE|6'
            connectionStrings: [
                {
                    name: 'AppConfig'
                    connectionString: listKeys(config.id, config.apiVersion).value[0].connectionString
                }
            ]
        }
        scmSiteAlsoStopped: false
        clientAffinityEnabled: true
        clientCertEnabled: false
        clientCertMode: 'Required'
        hostNamesDisabled: false
        customDomainVerificationId: '40BF7B86C2FCFDDFCAF1DB349DF5DEE2661093DBD1F889FA84ED4AAB4DA8B993'
        containerSize: 0
        dailyMemoryTimeQuota: 0
        httpsOnly: true
        redundancyMode: 'None'
        storageAccountRequired: false
        keyVaultReferenceIdentity: 'SystemAssigned'
    }

    resource appSettings 'config@2021-02-01' = {
        name: 'appsettings'
        properties: {
            // 'APPINSIGHTS_INSTRUMENTATIONKEY': instrumentationKey
            // 'ApplicationInsights:InstrumentationKey': instrumentationKey
        }
    }
}
//  resource sites_CTMBlazorSvrClient20230409134317_name_ftp 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2022-09-01' = {
//    parent: website
//    name: 'ftp'
//    location: location
//    properties: {
//      allow: true
//    }
//  }

//  resource sites_CTMBlazorSvrClient20230409134317_name_scm 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2022-09-01' = {
//    parent: website
//    name: 'scm'
//    location: location
//    properties: {
//      allow: true
//    }
//  }

resource sites_CTMBlazorSvrClient20230409134317_name_web 'Microsoft.Web/sites/config@2022-09-01' = {
    parent: website
    name: 'web'
    properties: {
        numberOfWorkers: 1
        defaultDocuments: [
            'Default.htm'
            'Default.html'
            'Default.asp'
            'index.htm'
            'index.html'
            'iisstart.htm'
            'default.aspx'
            'index.php'
            'hostingstart.html'
        ]
        netFrameworkVersion: 'v7.0'
        phpVersion: '5.6'
        requestTracingEnabled: false
        remoteDebuggingEnabled: false
        httpLoggingEnabled: false
        acrUseManagedIdentityCreds: false
        logsDirectorySizeLimit: 35
        detailedErrorLoggingEnabled: false
        publishingUsername: '$CTMBlazorSvrClient20230409134317'
        scmType: 'None'
        use32BitWorkerProcess: true
        webSocketsEnabled: false
        alwaysOn: false
        managedPipelineMode: 'Integrated'
        virtualApplications: [
            {
                virtualPath: '/'
                physicalPath: 'site\\wwwroot'
                preloadEnabled: false
            }
        ]
        loadBalancing: 'LeastRequests'
        experiments: {
            rampUpRules: []
        }
        autoHealEnabled: false
        vnetRouteAllEnabled: false
        vnetPrivatePortsCount: 0
        localMySqlEnabled: false
        managedServiceIdentityId: 24402
        ipSecurityRestrictions: [
            {
                ipAddress: 'Any'
                action: 'Allow'
                priority: 2147483647
                name: 'Allow all'
                description: 'Allow all access'
            }
        ]
        scmIpSecurityRestrictions: [
            {
                ipAddress: 'Any'
                action: 'Allow'
                priority: 2147483647
                name: 'Allow all'
                description: 'Allow all access'
            }
        ]
        scmIpSecurityRestrictionsUseMain: false
        http20Enabled: false
        minTlsVersion: '1.2'
        scmMinTlsVersion: '1.2'
        ftpsState: 'FtpsOnly'
        preWarmedInstanceCount: 0
        elasticWebAppScaleLimit: 0
        functionsRuntimeScaleMonitoringEnabled: false
        minimumElasticInstanceCount: 0
        azureStorageAccounts: {}
    }
}

resource sites_CTMBlazorSvrClient20230409134317_name_sites_CTMBlazorSvrClient20230409134317_name_azurewebsites_net 'Microsoft.Web/sites/hostNameBindings@2022-09-01' = {
    parent: website
    name: '${website.name}.azurewebsites.net'
    properties: {
        siteName: 'CTMBlazorSvrClient20230409134317'
        hostNameType: 'Verified'
    }
}

resource sites_CTMBlazorSvrClient20230409134317_name_Microsoft_AspNetCore_AzureAppServices_SiteExtension 'Microsoft.Web/sites/siteextensions@2022-09-01' = {
    parent: website
    name: 'Microsoft.AspNetCore.AzureAppServices.SiteExtension'
}

resource stgCrewTaskMgrAuthFunc 'Microsoft.Storage/storageAccounts@2022-09-01' = {
    name: '${name}stgctmfunc'
    location: location
    tags: {
        'hidden-related:/providers/Microsoft.Web/sites/funcCrewTaskMgrAuthenticatedServices': 'empty'
    }
    sku: {
        name: 'Standard_LRS'
    }
    kind: 'Storage'
    properties: {
        minimumTlsVersion: 'TLS1_0'
        allowBlobPublicAccess: true
        networkAcls: {
            bypass: 'AzureServices'
            virtualNetworkRules: []
            ipRules: []
            defaultAction: 'Allow'
        }
        supportsHttpsTrafficOnly: true
        encryption: {
            services: {
                file: {
                    keyType: 'Account'
                    enabled: true
                }
                blob: {
                    keyType: 'Account'
                    enabled: true
                }
            }
            keySource: 'Microsoft.Storage'
        }
    }
    resource stgCrewTaskMgrAuthFuncBlobSvcs 'blobServices@2022-09-01' = {
        name: 'default'
        properties: {
            cors: {
                corsRules: []
            }
            deleteRetentionPolicy: {
                allowPermanentDelete: false
                enabled: false
            }
        }

        resource storageAccounts_stgcrewtaskmgrauthfunc_name_default_azure_webjobs_hosts 'containers@2022-09-01' = {
            name: 'azure-webjobs-hosts'
            properties: {
                immutableStorageWithVersioning: {
                    enabled: false
                }
                defaultEncryptionScope: '$account-encryption-key'
                denyEncryptionScopeOverride: false
                publicAccess: 'None'
            }
        }
        resource storageAccounts_stgcrewtaskmgrauthfunc_name_default_azure_webjobs_secrets 'containers@2022-09-01' = {
            name: 'azure-webjobs-secrets'
            properties: {
                immutableStorageWithVersioning: {
                    enabled: false
                }
                defaultEncryptionScope: '$account-encryption-key'
                denyEncryptionScopeOverride: false
                publicAccess: 'None'
            }
        }

        resource storageAccounts_stgcrewtaskmgrauthfunc_name_default_scm_releases 'containers@2022-09-01' = {
            name: 'scm-releases'
            properties: {
                immutableStorageWithVersioning: {
                    enabled: false
                }
                defaultEncryptionScope: '$account-encryption-key'
                denyEncryptionScopeOverride: false
                publicAccess: 'None'
            }
        }
    }
    resource stgCrewTaskMgrAuthFuncFileSvcs 'fileServices@2022-09-01' = {
        name: 'default'
        properties: {
            protocolSettings: {
                smb: {}
            }
            cors: {
                corsRules: []
            }
            shareDeleteRetentionPolicy: {
                enabled: true
                days: 7
            }
        }

        resource stgCrewTaskMgrAuthFuncShare_CrewTaskMgrAuthenticatedSvcs 'shares@2022-09-01' = {
            name: 'crewtaskmgrauthenticatedsvcs'
            properties: {
                accessTier: 'TransactionOptimized'
                shareQuota: 5120
                enabledProtocols: 'SMB'
            }
        }

        resource stgCrewTaskMgrAuthFuncShare_CrewTaskMgrAuthenticatedSvsMissSpell 'shares@2022-09-01' = {
            name: 'crewtaskmgrauthenticatedsvs'
            properties: {
                accessTier: 'TransactionOptimized'
                shareQuota: 5120
                enabledProtocols: 'SMB'
            }
        }
        
        resource stgCrewTaskMgrAuthFuncShare_funcCrewTaskMgrAuthenticatedSvcs 'shares@2022-09-01' = {
            name: '${name}-func-CrewTaskMgrAuthSvcs'
            properties: {
                accessTier: 'TransactionOptimized'
                shareQuota: 5120
                enabledProtocols: 'SMB'
            }
        }
        resource stgCrewTaskMgrAuthFuncShare_funcCrewTaskMgrAuthenticatedServices 'shares@2022-09-01' = {
            name: 'funccrewtaskmgrauthenticatedservices'
            properties: {
                accessTier: 'TransactionOptimized'
                shareQuota: 5120
                enabledProtocols: 'SMB'
            }
        }

        resource stgCrewTaskMgrauthFuncShare_funcCrewTaskMgrAuthenticatedServices841261e18dce 'shares@2022-09-01' = {
            name: 'funccrewtaskmgrauthenticatedservices841261e18dce'
            properties: {
                accessTier: 'TransactionOptimized'
                shareQuota: 5120
                enabledProtocols: 'SMB'
            }
        }

        resource stgCrewTaskMgrAuthFuncsShare_funcCrewTaskMgrAuthenticatedServicesec16e429bef8 'shares@2022-09-01' = {
            name: 'funccrewtaskmgrauthenticatedservicesec16e429bef8'
            properties: {
                accessTier: 'TransactionOptimized'
                shareQuota: 5120
                enabledProtocols: 'SMB'
            }
        }

        resource storageAccounts_stgcrewtaskmgrauthfunc_name_default_funccrewtaskmgrauthenticatedservicesfc1bb58b4a97 'shares@2022-09-01' = {
            name: 'funccrewtaskmgrauthenticatedservicesfc1bb58b4a97'
            properties: {
                accessTier: 'TransactionOptimized'
                shareQuota: 5120
                enabledProtocols: 'SMB'
            }
        }
    }

    resource stgCrewTaskMgrAuthFuncQueueSvcs 'queueServices@2022-09-01' = {
        name: 'default'
        properties: {
            cors: {
                corsRules: []
            }
        }
    }

    resource stgCrewTaskMgrAuthFuncTableSvcs 'tableServices@2022-09-01' = {
        name: 'default'
        properties: {
            cors: {
                corsRules: []
            }
        }
    }
}


// Determine our connection string

var blobStorageConnectionString = 'DefaultEndpointsProtocol=https;AccountName=${stgCrewTaskMgrAuthFunc.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${stgCrewTaskMgrAuthFunc.listKeys().keys[0].value}'

// Output our variable

output blobStorageConnectionString string = blobStorageConnectionString

resource funcCrewTaskMgrAuthSvsPlan 'Microsoft.Web/serverfarms@2022-09-01' = {
    name: '${name}-func-plan-CrewTaskMgrAuthSvcs'
    location: location
    sku: {
        name: 'Y1'
        tier: 'Dynamic'
        size: 'Y1'
        family: 'Y'
        capacity: 0
    }
    kind: 'functionapp'
    properties: {
        perSiteScaling: false
        elasticScaleEnabled: false
        maximumElasticWorkerCount: 1
        isSpot: false
        reserved: false
        isXenon: false
        hyperV: false
        targetWorkerCount: 0
        targetWorkerSizeId: 0
        zoneRedundant: false
    }
}

resource funcCrewTaskMgrAuthSvcs 'Microsoft.Web/sites@2022-09-01' = {
    name: '${name}-func-CrewTaskMgrAuthSvcs'
    location: location
    tags: {
        'hidden-link: /app-insights-resource-id': '/subscriptions/acc26051-92a5-4ed1-a226-64a187bc27db/resourceGroups/rg_CrewTaskMgr/providers/microsoft.insights/components/appInsCrewTaskMgrAuthenticatedServices'
        'hidden-link: /app-insights-instrumentation-key': '8a8d6ab1-bf12-4290-9d4d-3fea26fa6bb6'
        'hidden-link: /app-insights-conn-string': 'InstrumentationKey=8a8d6ab1-bf12-4290-9d4d-3fea26fa6bb6;IngestionEndpoint=https://westus2-2.in.applicationinsights.azure.com/;LiveEndpoint=https://westus2.livediagnostics.monitor.azure.com/'
    }
    kind: 'functionapp'
    properties: {
        enabled: true
        hostNameSslStates: [

            {
                name: 'crewtaskmgrauthenticatedservices.azurewebsites.net'
                sslState: 'Disabled'
                hostType: 'Standard'
            }
            {
                name: 'crewtaskmgrauthenticatedservices.scm.azurewebsites.net'
                sslState: 'Disabled'
                hostType: 'Repository'
            }
        ]
        serverFarmId: funcCrewTaskMgrAuthSvsPlan.id
        reserved: false
        isXenon: false
        hyperV: false
        vnetRouteAllEnabled: false
        vnetImagePullEnabled: false
        vnetContentShareEnabled: false
        siteConfig: {
            numberOfWorkers: 1
            acrUseManagedIdentityCreds: false
            alwaysOn: false
            http20Enabled: false
            functionAppScaleLimit: 200
            minimumElasticInstanceCount: 0
        }
        scmSiteAlsoStopped: false
        clientAffinityEnabled: false
        clientCertEnabled: false
        clientCertMode: 'Required'
        hostNamesDisabled: false
        customDomainVerificationId: '40BF7B86C2FCFDDFCAF1DB349DF5DEE2661093DBD1F889FA84ED4AAB4DA8B993'
        containerSize: 1536
        dailyMemoryTimeQuota: 0
        httpsOnly: true
        redundancyMode: 'None'
        storageAccountRequired: false
        keyVaultReferenceIdentity: 'SystemAssigned'
    }
    resource authsettigns 'config@2022-09-01' = {
        name: 'authsettingsV2'
        properties: {
            platform: {
                enabled: requireAuthentication
                runtimeVersion: '~1'
            }
            globalValidation: {
                requireAuthentication: requireAuthentication
                unauthenticatedClientAction: 'RedirectToLoginPage'
                redirectToProvider: 'azureactivedirectory'
            }
            identityProviders: {
                azureActiveDirectory: requireAuthentication ? {
                    enabled: requireAuthentication
                    registration: {
                        openIdIssuer: 'https://enterprisedemoorg.b2clogin.com/enterprisedemoorg.onmicrosoft.com/v2.0/.well-known/openid-configuration?p=B2C_1_Frontend_APIM_Totorial_SUSI' // 'https://sts.windows.net/${subscription().tenantId}/v2.0'
                        clientId: applicationId
                        clientSecretSettingName: 'MICROSOFT_PROVIDER_AUTHENTICATION_SECRET'
                    }
                    login: {
                        disableWWWAuthenticate: false
                    }
                    validation: {
                        jwtClaimChecks: {}
                        allowedAudiences: [
                            'api://${applicationId}'
                        ]
                        defaultAuthorizationPolicy: {
                            allowedPrincipals: {}
                        }
                    }
                } : null
            }
            login: {
                routes: {}
                tokenStore: {
                    enabled: true
                    tokenRefreshExtensionHours: json('72.0')
                    fileSystem: {}
                    azureBlobStorage: {}
                }
                preserveUrlFragmentsForLogins: false
                cookieExpiration: {
                    convention: 'FixedTime'
                    timeToExpiration: '08:00:00'
                }
                nonce: {
                    validateNonce: true
                    nonceExpirationInterval: '00:05:00'
                }
            }
            httpSettings: {
                requireHttps: true
                routes: {
                    apiPrefix: '/.auth'
                }
                forwardProxy: {
                    convention: 'NoProxy'
                }
            }
        }
    }
    resource appSettings 'config@2021-02-01' = {
        name: 'appsettings'
        properties: {
            // 'APPINSIGHTS_INSTRUMENTATIONKEY': instrumentationKey
            // 'ApplicationInsights:InstrumentationKey': instrumentationKey
            'APPLICATIONINSIGHTS_CONNECTION_STRING': ApplicationInsights_ConnectionString
            'Logging:ApplicationInsights:Enabled': 'true'
            'Logging:ApplicationInsights:LogLevel': 'Trace'
            'Logging:LogLevel:Default': 'Trace'
            'Logging.LogLevel:Microsoft': 'Trace'
            'COSMOS_GP_ENDPOINT': '${cosmosEndPoint}'
            'COSMOS_GP_ACCOUNTKEY':  '${cosmosAccountKey}'
            'ASPNETCORE_ENVIRONMENT': 'Development'
            'MICROSOFT_PROVIDER_AUTHENTICATION_SECRET':  '${BackEndClientSecret}'
            'AzureWebJobsStorage': blobStorageConnectionString
        }
    }
    resource sites_CrewTaskMgrAuthenticatedSvcs_name_Hello 'functions@2022-09-01' = {
        name: 'Hello'
        properties: {
            script_root_path_href: 'https://${funcCrewTaskMgrAuthSvcsName}.azurewebsites.net/admin/vfs/site/wwwroot/Hello/'
            script_href: 'https://${funcCrewTaskMgrAuthSvcsName}.azurewebsites.net/admin/vfs/site/wwwroot/bin/CrewTaskMgrAuthenticatedServices.dll'
            config_href: 'https://${funcCrewTaskMgrAuthSvcsName}.azurewebsites.net/admin/vfs/site/wwwroot/Hello/function.json'
            test_data_href: 'https://${funcCrewTaskMgrAuthSvcsName}.azurewebsites.net/admin/vfs/data/Functions/sampledata/Hello.dat'
            href: 'https://${funcCrewTaskMgrAuthSvcsName}.azurewebsites.net/admin/functions/Hello'
            config: {}
            invoke_url_template: 'https://${funcCrewTaskMgrAuthSvcsName}.azurewebsites.net/api/hello'
            language: 'DotNetAssembly'
            isDisabled: false
        }
    }
    dependsOn:[
       stgCrewTaskMgrAuthFunc
    ]
}

param components_appinsCrewTaskMgrAuthenticatedServices_externalid string = '/subscriptions/acc26051-92a5-4ed1-a226-64a187bc27db/resourceGroups/rg_CrewTaskMgr/providers/microsoft.insights/components/appinsCrewTaskMgrAuthenticatedServices'
param apimCrewTaskMgtName string = '${name}-apim'
resource apimCrewTaskMgt_resource 'Microsoft.ApiManagement/service@2022-08-01' = {
    name: apimCrewTaskMgtName
    location: location
    sku: {
        name: 'Consumption'
        capacity: 0
    }
    identity: {
        type: 'SystemAssigned'
    }
    properties: {
        publisherEmail: 'sheintze@hotmail.com'
        publisherName: 'WaveCentric'
        notificationSenderEmail: 'apimgmt-noreply@mail.windowsazure.com'
        hostnameConfigurations: [
            {
                type: 'Proxy'
                hostName: '${apimCrewTaskMgtName}.azure-api.net'
                negotiateClientCertificate: false
                defaultSslBinding: true
                certificateSource: 'BuiltIn'
            }
        ]
        customProperties: {
            'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls11': 'true'
            'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10': 'true'
            'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Tls11': 'true'
            'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Tls10': 'true'
            'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Ssl30': 'true'
            'Microsoft.WindowsAzure.ApiManagement.Gateway.Protocols.Server.Http2': 'true'
        }
        virtualNetworkType: 'None'
        disableGateway: false
        natGatewayState: 'Disabled'
        apiVersionConstraint: {}
        publicNetworkAccess: 'Enabled'
    }

    resource ApiCrewTaskMgrAuthenticatedSvcs 'apis@2022-08-01' = {
        name: 'crewtaskmgrauthenticatedsvcs'
        properties: {
            displayName: 'CrewTaskMgrAuthenticatedSvcs'
            apiRevision: '1'
            description: 'Import from "CrewTaskMgrAuthenticatedSvcs" Function App'
            subscriptionRequired: true
            path: 'CrewTaskMgrAuthenticatedSvcs'
            protocols: [
                'https'
            ]
            authenticationSettings: {
                oAuth2AuthenticationSettings: []
                openidAuthenticationSettings: []
            }
            subscriptionKeyParameterNames: {
                header: 'Ocp-Apim-Subscription-Key'
                query: 'subscription-key'
            }
            isCurrent: true
        }
        resource ApiCrewTaskMgrAuthenticatedSvcs_get_hello 'operations@2022-08-01' = {
            name: 'get-hello'
            properties: {
                displayName: 'Hello'
                method: 'GET'
                urlTemplate: '/Hello'
                templateParameters: []
                responses: []
            }

            resource ApiCrewTaskMgrAuthenticatedSvcs_get_hello_policy 'policies@2022-08-01' = {
                name: 'policy'
                properties: {
                    value: '<policies>\r\n  <inbound>\r\n    <base />\r\n    <set-backend-service id="apim-generated-policy" backend-id="${name}-func-CrewTaskMgrAuthSvcs" />\r\n  </inbound>\r\n  <backend>\r\n    <base />\r\n  </backend>\r\n  <outbound>\r\n    <base />\r\n  </outbound>\r\n  <on-error>\r\n    <base />\r\n  </on-error>\r\n</policies>'
                    format: 'xml'
                }
                dependsOn: [
                    funcCrewTaskMgrAuthSvcs
                    ApiCrewTaskMgrAuthenticatedSvcs
                    apimCrewTaskMgt_resource
                ]
            }
        }
    }
// begin Error somewhere here
    resource ApiCrewTaskMgrAuthenticatedSvcs_post_hello 'operations@2022-08-01' = {
        name: 'post-hello'
        properties: {
            displayName: 'Hello'
            method: 'POST'
            urlTemplate: '/Hello'
            templateParameters: []
            responses: []
        }
    }

    // resource apimCrewTaskMgt_func_csharp_script_demo 'apis@2022-08-01' = // {
    //     name: 'func-csharp-script-demo'
    //     properties: {
    //         displayName: 'func-csharp-script-demo'
    //         apiRevision: '1'
    //         description: 'Import from "func-csharp-script-demo" Function App'
    //         subscriptionRequired: false
    //         path: 'func-csharp-script-demo'
    //         protocols: [
    //             'https'
    //         ]
    //         authenticationSettings: {
    //             oAuth2AuthenticationSettings: []
    //             openidAuthenticationSettings: []
    //         }
    //         subscriptionKeyParameterNames: {
    //             header: 'Ocp-Apim-Subscription-Key'
    //             query: 'subscription-key'
    //         }
    //         isCurrent: true
    //     }
    //     resource apimCrewTaskMgt_func_csharp_script_demo_get_hello 'operations@2022-08-01' = {
    //         name: 'get-hello'
    //         properties: {
    //             displayName: 'Hello'
    //             method: 'GET'
    //             urlTemplate: '/Hello'
    //             templateParameters: []
    //             responses: []
    //         }
    //     }
    //     resource ApiCrewTaskMgrAuthenticatedSvcs_post_hello_policy 'policies@2022-08-01' = {
    //         name: 'policy1'
    //         properties: {
    //             value: '<policies>\r\n  <inbound>\r\n    <base />\r\n    <set-backend-service id="apim-generated-policy" backend-id="crewtaskmgrauthenticatedsvcs" />\r\n  </inbound>\r\n  <backend>\r\n    <base />\r\n  </backend>\r\n  <outbound>\r\n    <base />\r\n  </outbound>\r\n  <on-error>\r\n    <base />\r\n  </on-error>\r\n</policies>'
    //             format: 'xml'
    //         }
    //         dependsOn: [
    //             ApiCrewTaskMgrAuthenticatedSvcs
    //             apimCrewTaskMgt_resource
    //         ]
    //     }
    //     resource apimCrewTaskMgt_func_csharp_script_demo_get_hello_policy 'policies@2022-08-01' = {

    //         name: 'policy2'
    //         properties: {
    //             value: '<policies>\r\n  <inbound>\r\n    <base />\r\n    <set-backend-service id="apim-generated-policy" backend-id="func-csharp-script-demo" />\r\n  </inbound>\r\n  <backend>\r\n    <base />\r\n  </backend>\r\n  <outbound>\r\n    <base />\r\n  </outbound>\r\n  <on-error>\r\n    <base />\r\n  </on-error>\r\n</policies>'
    //             format: 'xml'
    //         }
    //     }
    // }

    resource BackEnd_ApiCrewTaskMgrAuthenticatedSvcs 'backends@2022-08-01' = {
        name: 'crewtaskmgrauthenticatedsvcs'
        properties: {
            description: 'CrewTaskMgrAuthenticatedSvcs'
            url: 'https://crewtaskmgrauthenticatedsvcs.azurewebsites.net/api'
            protocol: 'http'
            resourceId: 'https://management.azure.com/subscriptions/acc26051-92a5-4ed1-a226-64a187bc27db/resourceGroups/rg_CrewTaskMgr/providers/Microsoft.Web/sites/CrewTaskMgrAuthenticatedSvcs'
            credentials: {
                header: {
                    'x-functions-key': [
                        '{{crewtaskmgrauthenticatedsvcs-key}}'
                    ]
                }
            }
        }
    }
    
    resource apimCrewTaskMgt_funccrewtaskmgrauthenticatedservices 'backends@2022-08-01' = {
        name: 'funccrewtaskmgrauthenticatedservices'
        properties: {
            description: 'funcCrewTaskMgrAuthenticatedServices'
            url: 'https://funccrewtaskmgrauthenticatedservices.azurewebsites.net/api'
            protocol: 'http'
            resourceId: 'https://management.azure.com/subscriptions/acc26051-92a5-4ed1-a226-64a187bc27db/resourceGroups/rg_CrewTaskMgr/providers/Microsoft.Web/sites/funcCrewTaskMgrAuthenticatedServices'
            credentials: {
                header: {
                    'x-functions-key': [
                        '{{funccrewtaskmgrauthenticatedservices-key}}'
                    ]
                }
            }
        }
    }
    // resource BackEnd_apimCrewTaskMgt_func_csharp_script_demo 'backends@2022-08-01' = // {
    //     name: 'func-csharp-script-demo'
    //     properties: {
    //         description: 'func-csharp-script-demo'
    //         url: 'https://func-csharp-script-demo.azurewebsites.net/api'
    //         protocol: 'http'
    //         resourceId: 'https://management.azure.com/subscriptions/acc26051-92a5-4ed1-a226-64a187bc27db/resourceGroups/rg_csharp_script_demo/providers/Microsoft.Web/sites/func-csharp-script-demo'
    //         credentials: {
    //             header: {
    //                 'x-functions-key': [
    //                     '{{func-csharp-script-demo-key}}'
    //                 ]
    //             }
    //         }
    //     }
    // }

    resource apimCrewTaskMgt_appinsCrewTaskMgrAuthenticatedServices 'loggers@2022-08-01' = {
        name: 'appinsCrewTaskMgrAuthenticatedServices'
        properties: {
            loggerType: 'applicationInsights'
            credentials: {
                instrumentationKey: '{{Logger-Credentials--644aea511aff160ccc6b04cd}}'
            }
            isBuffered: true
            resourceId: components_appinsCrewTaskMgrAuthenticatedServices_externalid
        }
    }

    resource apimCrewTaskMgt_644aea511aff160ccc6b04cc 'namedValues@2022-08-01' = {
        name: '644aea511aff160ccc6b04cc'
        properties: {
            displayName: 'Logger-Credentials--644aea511aff160ccc6b04cd'
            secret: true
        }
    }

    resource ApiCrewTaskMgrAuthenticatedSvcs_key 'namedValues@2022-08-01' = {
        name: 'crewtaskmgrauthenticatedsvcs-key'
        properties: {
            displayName: 'crewtaskmgrauthenticatedsvcs-key'
            tags: [
                'key'
                'function'
                'auto'
            ]
            secret: true
        }
    }

    resource apimCrewTaskMgt_funccrewtaskmgrauthenticatedservices_key 'namedValues@2022-08-01' = {
        name: 'funccrewtaskmgrauthenticatedservices-key'
        properties: {
            displayName: 'funccrewtaskmgrauthenticatedservices-key'
            tags: [
                'key'
                'function'
                'auto'
            ]
            secret: true
        }
    }

    // resource apimCrewTaskMgt_func_csharp_script_demo_key 'namedValues@2022-08-01' = // {
    //     name: 'func-csharp-script-demo-key'
    //     properties: {
    //         displayName: 'func-csharp-script-demo-key'
    //         tags: [
    //             'key'
    //             'function'
    //             'auto'
    //         ]
    //         secret: true
    //     }
    // }
 // end error region
    resource apimCrewTaskMgt_policy 'policies@2022-08-01' = {
        name: 'policy'
        properties: {
            value: '<!--\r\n    IMPORTANT:\r\n    - Policy elements can appear only within the <inbound>, <outbound>, <backend> section elements.\r\n    - Only the <forward-request> policy element can appear within the <backend> section element.\r\n    - To apply a policy to the incoming request (before it is forwarded to the backend service), place a corresponding policy element within the <inbound> section element.\r\n    - To apply a policy to the outgoing response (before it is sent back to the caller), place a corresponding policy element within the <outbound> section element.\r\n    - To add a policy position the cursor at the desired insertion point and click on the round button associated with the policy.\r\n    - To remove a policy, delete the corresponding policy statement from the policy document.\r\n    - Policies are applied in the order of their appearance, from the top down.\r\n-->\r\n<policies>\r\n  <inbound>\r\n    <cors allow-credentials="true">\r\n      <allowed-origins>\r\n        <origin>https://stgstaticwebprotectapim.z5.web.core.windows.net</origin>\r\n        <origin>https://jac3sukjdrxzi-web.azurewebsites.net</origin>\r\n      </allowed-origins>\r\n      <allowed-methods preflight-result-max-age="120">\r\n        <method>GET</method>\r\n      </allowed-methods>\r\n      <allowed-headers>\r\n        <header>*</header>\r\n      </allowed-headers>\r\n      <expose-headers>\r\n        <header>*</header>\r\n      </expose-headers>\r\n    </cors>\r\n    <validate-jwt header-name="Authorization" failed-validation-httpcode="401" failed-validation-error-message="Unauthorized. Access token is missing or invalid." require-expiration-time="true" require-signed-tokens="true" clock-skew="300">\r\n      <openid-config url="https://enterprisedemoorg.b2clogin.com/enterprisedemoorg.onmicrosoft.com/v2.0/.well-known/openid-configuration?p=B2C_1_Frontend_APIM_Totorial_SUSI" />\r\n      <required-claims>\r\n        <claim name="aud">\r\n          <value>0edb71aa-18a3-46d3-a3ee-6271489bd312</value>\r\n        </claim>\r\n      </required-claims>\r\n    </validate-jwt>\r\n  </inbound>\r\n  <backend>\r\n    <forward-request />\r\n  </backend>\r\n  <outbound />\r\n  <on-error />\r\n</policies>'
            format: 'xml'
        }
    }

    resource apimCrewTaskMgt_unlimited 'products@2022-08-01' = {
        name: 'unlimited'
        properties: {
            displayName: 'Unlimited'
            description: 'unlimited'
            subscriptionRequired: false
            state: 'notPublished'
        }

        resource apimCrewTaskMgt_unlimited_crewtaskmgrauthenticatedsvcs 'apis@2022-08-01' = {
            name: 'crewtaskmgrauthenticatedsvcs'
        }
    }

    resource apimPropertiesCrewTaskMgt_644aea511aff160ccc6b04cc 'properties@2019-01-01' = {
        name: '644aea511aff160ccc6b04cc'
        properties: {
            displayName: 'Logger-Credentials--644aea511aff160ccc6b04cd'
            value: 'c71b3ac4-9f20-4465-9963-0737c42218a0'
            secret: true
        }
    }

    resource apimPropertiesKeyCrewTaskMgrAuthenticatedSvcs 'properties@2019-01-01' = {
        name: 'crewtaskmgrauthenticatedsvcs-key'
        properties: {
            displayName: 'crewtaskmgrauthenticatedsvcs-key'
            value: 'i-aZx0ei-uVAOcfFO9tQBKK0WlYS2Q-E3VyuETG32Tz8AzFuWsftpg=='
            tags: [
                'key'
                'function'
                'auto'
            ]
            secret: true
        }
    }

    resource Microsoft_ApiManagement_service_properties_apimCrewTaskMgt_funccrewtaskmgrauthenticatedservices_key 'properties@2019-01-01' = {
        name: 'funccrewtaskmgrauthenticatedservices-key'
        properties: {
            displayName: 'funccrewtaskmgrauthenticatedservices-key'
            value: '_0dDDL8PTm0uk7FOg9-15Mh4NabSS5OMrRwdyrrfp_jFAzFuGggMKg=='
            tags: [
                'key'
                'function'
                'auto'
            ]
            secret: true
        }
    }

    // resource Microsoft_ApiManagement_service_properties_apimCrewTaskMgt_func_csharp_script_demo_key 'properties@2019-01-01' = // {
    //     name: 'func-csharp-script-demo-key'
    //     properties: {
    //         displayName: 'func-csharp-script-demo-key'
    //         value: '5ynmTm6/QDJCs9K8CWskwo5qK92AO3ImqK7PHIa4HfMP716kpWb6MQ=='
    //         tags: [
    //             'key'
    //             'function'
    //             'auto'
    //         ]
    //         secret: true
    //     }
    // }

    resource apimCrewTaskMgt_master 'subscriptions@2022-08-01' = {
        name: 'master'
        properties: {
            scope: '${apimCrewTaskMgt_resource.id}/'
            displayName: 'Built-in all-access subscription'
            state: 'active'
            allowTracing: false
        }
    }

    resource apimCrewTaskMgt_applicationinsights 'diagnostics@2022-08-01' = {
        name: 'applicationinsights'
        properties: {
            alwaysLog: 'allErrors'
            httpCorrelationProtocol: 'Legacy'
            logClientIp: true
            loggerId: apimCrewTaskMgt_appinsCrewTaskMgrAuthenticatedServices.id
            sampling: {
                samplingType: 'fixed'
                percentage: 100
            }
            frontend: {
                request: {
                    dataMasking: {
                        queryParams: [
                            {
                                value: '*'
                                mode: 'Hide'
                            }
                        ]
                    }
                }
            }
            backend: {
                request: {
                    dataMasking: {
                        queryParams: [
                            {
                                value: '*'
                                mode: 'Hide'
                            }
                        ]
                    }
                }
            }
        }
        resource apimCrewTaskMgt_applicationinsights_appinsCrewTaskMgrAuthenticatedServices 'loggers@2018-01-01' = {
            name: 'appinsCrewTaskMgrAuthenticatedServices'
        }
    }
    dependsOn: [
      funcCrewTaskMgrAuthSvcs
    ]
}

  //  No Build in Progress
  //  az functionapp delete --name jac3sukjdrxzi-func-CrewTaskMgrAuthSvcs --resource-group rg_CrewTaskMgr
  //  az storage account delete -n jac3sukjdrxzistgctmfunc -g rg_CrewTaskMgr --yes
  //  az apim delete --name jac3sukjdrxzi-apim --resource-group rg_CrewTaskMgr --yes
  //  az apim deletedservice purge --service-name jac3sukjdrxzi-apim --location westus
  //  ERROR: (ServiceNotFound) Api service does not exist: jac3sukjdrxzi-apim
  //  Code: ServiceNotFound
  //  Message: Api service does not exist: jac3sukjdrxzi-apim
  //  Previous shutdown/build is complete. Begin deployment build.
  //  az deployment group create --name CrewTaskMgr --resource-group rg_CrewTaskMgr --mode Incremental --template-file deploy-CrewTaskMgr.bicep --parameters ownerId=aaf5d00b-39ba-4fa2-b7b3-c28758956b14 @deploy.parameters.json
  //  WARNING: c:\Users\shein\source\repos\CrewTaskManager\CTMBlazorSvrClient\deploy-CrewTaskMgr.bicep(119,7) : Warning no-unused-params: Parameter "webPlanSku" is declared but never used. [https://aka.ms/bicep/linter/no-unused-params]
  //  c:\Users\shein\source\repos\CrewTaskManager\CTMBlazorSvrClient\deploy-CrewTaskMgr.bicep(165,40) : Warning outputs-should-not-contain-secrets: Outputs should not contain secrets. Found possible secret: function 'listKeys' [https://aka.ms/bicep/linter/outputs-should-not-contain-secrets]
  //  c:\Users\shein\source\repos\CrewTaskManager\CTMBlazorSvrClient\deploy-CrewTaskMgr.bicep(165,40) : Warning use-resource-symbol-reference: Use a resource reference instead of invoking function "listKeys". This simplifies the syntax and allows Bicep to better understand your deployment dependency graph. [https://aka.ms/bicep/linter/use-resource-symbol-reference]
  //  c:\Users\shein\source\repos\CrewTaskManager\CTMBlazorSvrClient\deploy-CrewTaskMgr.bicep(201,11) : Warning use-parent-property: Resource "kvaadb2cSecret" has its name formatted as a child of resource "kv". The syntax can be simplified by using the parent property. [https://aka.ms/bicep/linter/use-parent-property]
  //  c:\Users\shein\source\repos\CrewTaskManager\CTMBlazorSvrClient\deploy-CrewTaskMgr.bicep(210,7) : Warning no-unused-params: Parameter "cosmosAccountName" is declared but never used. [https://aka.ms/bicep/linter/no-unused-params]
  //  c:\Users\shein\source\repos\CrewTaskManager\CTMBlazorSvrClient\deploy-CrewTaskMgr.bicep(218,7) : Warning no-unused-params: Parameter "hostingPlanName" is declared but never used. [https://aka.ms/bicep/linter/no-unused-params]
  //  c:\Users\shein\source\repos\CrewTaskManager\CTMBlazorSvrClient\deploy-CrewTaskMgr.bicep(220,28) : Warning outputs-should-not-contain-secrets: Outputs should not contain secrets. Found possible secret: secure parameter 'cosmosAccountKey' [https://aka.ms/bicep/linter/outputs-should-not-contain-secrets]
  //  c:\Users\shein\source\repos\CrewTaskManager\CTMBlazorSvrClient\deploy-CrewTaskMgr.bicep(221,26) : Warning outputs-should-not-contain-secrets: Outputs should not contain secrets. Found possible secret: secure parameter 'cosmosEndPoint' [https://aka.ms/bicep/linter/outputs-should-not-contain-secrets]
  //  c:\Users\shein\source\repos\CrewTaskManager\CTMBlazorSvrClient\deploy-CrewTaskMgr.bicep(323,39) : Warning use-resource-symbol-reference: Use a resource reference instead of invoking function "listKeys". This simplifies the syntax and allows Bicep to better understand your deployment dependency graph. [https://aka.ms/bicep/linter/use-resource-symbol-reference]
  //  c:\Users\shein\source\repos\CrewTaskManager\CTMBlazorSvrClient\deploy-CrewTaskMgr.bicep(790,13) : Warning prefer-unquoted-property-names: Property names that are valid identifiers should be declared without quotation marks and accessed using dot notation. [https://aka.ms/bicep/linter/prefer-unquoted-property-names]
  //  c:\Users\shein\source\repos\CrewTaskManager\CTMBlazorSvrClient\deploy-CrewTaskMgr.bicep(795,13) : Warning prefer-unquoted-property-names: Property names that are valid identifiers should be declared without quotation marks and accessed using dot notation. [https://aka.ms/bicep/linter/prefer-unquoted-property-names]
  //  c:\Users\shein\source\repos\CrewTaskManager\CTMBlazorSvrClient\deploy-CrewTaskMgr.bicep(795,35) : Warning simplify-interpolation: Remove unnecessary string interpolation. [https://aka.ms/bicep/linter/simplify-interpolation]
  //  c:\Users\shein\source\repos\CrewTaskManager\CTMBlazorSvrClient\deploy-CrewTaskMgr.bicep(796,13) : Warning prefer-unquoted-property-names: Property names that are valid identifiers should be declared without quotation marks and accessed using dot notation. [https://aka.ms/bicep/linter/prefer-unquoted-property-names]
  //  c:\Users\shein\source\repos\CrewTaskManager\CTMBlazorSvrClient\deploy-CrewTaskMgr.bicep(796,38) : Warning simplify-interpolation: Remove unnecessary string interpolation. [https://aka.ms/bicep/linter/simplify-interpolation]
  //  c:\Users\shein\source\repos\CrewTaskManager\CTMBlazorSvrClient\deploy-CrewTaskMgr.bicep(797,13) : Warning prefer-unquoted-property-names: Property names that are valid identifiers should be declared without quotation marks and accessed using dot notation. [https://aka.ms/bicep/linter/prefer-unquoted-property-names]
  //  c:\Users\shein\source\repos\CrewTaskManager\CTMBlazorSvrClient\deploy-CrewTaskMgr.bicep(798,13) : Warning prefer-unquoted-property-names: Property names that are valid identifiers should be declared without quotation marks and accessed using dot notation. [https://aka.ms/bicep/linter/prefer-unquoted-property-names]
  //  c:\Users\shein\source\repos\CrewTaskManager\CTMBlazorSvrClient\deploy-CrewTaskMgr.bicep(798,58) : Warning simplify-interpolation: Remove unnecessary string interpolation. [https://aka.ms/bicep/linter/simplify-interpolation]
  //  c:\Users\shein\source\repos\CrewTaskManager\CTMBlazorSvrClient\deploy-CrewTaskMgr.bicep(799,13) : Warning prefer-unquoted-property-names: Property names that are valid identifiers should be declared without quotation marks and accessed using dot notation. [https://aka.ms/bicep/linter/prefer-unquoted-property-names]
  //  c:\Users\shein\source\repos\CrewTaskManager\CTMBlazorSvrClient\deploy-CrewTaskMgr.bicep(900,21) : Warning no-unnecessary-dependson: Remove unnecessary dependsOn entry 'ApiCrewTaskMgrAuthenticatedSvcs'. [https://aka.ms/bicep/linter/no-unnecessary-dependson]
  //  c:\Users\shein\source\repos\CrewTaskManager\CTMBlazorSvrClient\deploy-CrewTaskMgr.bicep(901,21) : Warning no-unnecessary-dependson: Remove unnecessary dependsOn entry 'apimCrewTaskMgt_resource'. [https://aka.ms/bicep/linter/no-unnecessary-dependson]
  //  c:\Users\shein\source\repos\CrewTaskManager\CTMBlazorSvrClient\deploy-CrewTaskMgr.bicep(907,57) : Warning BCP081: Resource type "Microsoft.ApiManagement/service/operations@2022-08-01" does not have types available.
  //  c:\Users\shein\source\repos\CrewTaskManager\CTMBlazorSvrClient\deploy-CrewTaskMgr.bicep(976,34) : Warning no-hardcoded-env-urls: Environment URLs should not be hardcoded. Use the environment() function to ensure compatibility across clouds. Found this disallowed host: "management.azure.com" [https://aka.ms/bicep/linter/no-hardcoded-env-urls]
  //  c:\Users\shein\source\repos\CrewTaskManager\CTMBlazorSvrClient\deploy-CrewTaskMgr.bicep(993,34) : Warning no-hardcoded-env-urls: Environment URLs should not be hardcoded. Use the environment() function to ensure compatibility across clouds. Found this disallowed host: "management.azure.com" [https://aka.ms/bicep/linter/no-hardcoded-env-urls]
  //  c:\Users\shein\source\repos\CrewTaskManager\CTMBlazorSvrClient\deploy-CrewTaskMgr.bicep(1082,1064) : Warning no-hardcoded-env-urls: Environment URLs should not be hardcoded. Use the environment() function to ensure compatibility across clouds. Found this disallowed host: "core.windows.net" [https://aka.ms/bicep/linter/no-hardcoded-env-urls]
  //  
  //  ERROR: {
  //    "status": "Failed",
  //    "error": {
  //      "code": "DeploymentFailed",
  //      "target": "/subscriptions/acc26051-92a5-4ed1-a226-64a187bc27db/resourceGroups/rg_CrewTaskMgr/providers/Microsoft.Resources/deployments/CrewTaskMgr",
  //      "message": "At least one resource deployment operation failed. Please list deployment operations for details. Please see https://aka.ms/arm-deployment-operations for usage details.",
  //      "details": [
  //        {
  //          "code": "ValidationError",
  //          "message": "One or more fields contain incorrect values:",
  //          "details": [
  //            {
  //              "code": "ValidationError",
  //              "target": "set-backend-service",
  //              "message": "Error in element 'set-backend-service' on line 4, column 6: Backend with id 'jac3sukjdrxzi-func-CrewTaskMgrAuthSvcs' could not be found."
  //            }
  //          ]
  //        },
  //        {
  //          "code": "ValidationError",
  //          "message": "One or more fields contain incorrect values:",
  //          "details": [
  //            {
  //              "code": "ValidationError",
  //              "target": "credentials",
  //              "message": "Property 'funccrewtaskmgrauthenticatedservices-key' not found."
  //            }
  //          ]
  //        },
  //        {
  //          "code": "ValidationError",
  //          "message": "One or more fields contain incorrect values:",
  //          "details": [
  //            {
  //              "code": "ValidationError",
  //              "target": "credentials",
  //              "message": "Property 'crewtaskmgrauthenticatedsvcs-key' not found."
  //            }
  //          ]
  //        },
  //        {
  //          "code": "ValidationError",
  //          "message": "One or more fields contain incorrect values:",
  //          "details": [
  //            {
  //              "code": "ValidationError",
  //              "target": "value",
  //              "message": "Either Value or Keyvault must be provided."
  //            }
  //          ]
  //        },
  //        {
  //          "code": "ValidationError",
  //          "message": "One or more fields contain incorrect values:",
  //          "details": [
  //            {
  //              "code": "ValidationError",
  //              "target": "value",
  //              "message": "Either Value or Keyvault must be provided."
  //            }
  //          ]
  //        },
  //        {
  //          "code": "ValidationError",
  //          "message": "One or more fields contain incorrect values:",
  //          "details": [
  //            {
  //              "code": "ValidationError",
  //              "target": "One or more Properties ['{0}'] specified are missing.",
  //              "message": "Logger-Credentials--644aea511aff160ccc6b04cd"
  //            }
  //          ]
  //        },
  //        {
  //          "code": "ValidationError",
  //          "message": "One or more fields contain incorrect values:",
  //          "details": [
  //            {
  //              "code": "ValidationError",
  //              "target": "scope",
  //              "message": "Subscription scope should be one of '/apis', '/apis/{apiId}', '/products/{productId}'"
  //            }
  //          ]
  //        },
  //        {
  //          "code": "ValidationError",
  //          "message": "One or more fields contain incorrect values:",
  //          "details": [
  //            {
  //              "code": "ValidationError",
  //              "target": "value",
  //              "message": "Either Value or Keyvault must be provided."
  //            }
  //          ]
  //        },
  //        {
  //          "code": "BadRequest",
  //          "message": ""
  //        },
  //        {
  //          "code": "InvalidXmlDocument",
  //          "message": "XML specified is not syntactically valid.\nRequestId:cbb8f3d9-b01a-0000-0e92-878637000000\nTime:2023-05-16T01:03:28.5487386Z"
  //        }
  //      ]
  //    }
  //  }
  //  
  //  Name                                                        ResourceType                                        Region    Flavor
  //  ----------------------------------------------------------  --------------------------------------------------  --------  -----------
  //  Failure Anomalies - appinsCrewTaskMgrAuthenticatedServices  microsoft.alertsmanagement/smartDetectorAlertRules  global
  //  Failure Anomalies - funcCrewTaskMgrAuthenticatedServices    microsoft.alertsmanagement/smartDetectorAlertRules  global
  //  jac3sukjdrxzi-apim                                          Microsoft.ApiManagement/service                     westus
  //  protectapimfuncwithaadb2c004                                Microsoft.ApiManagement/service                     westus2
  //  jac3sukjdrxzi-config                                        Microsoft.AppConfiguration/configurationStores      westus
  //  appInsCrewTaskMgrAuthenticatedServices                      microsoft.insights/components                       westus2   web
  //  jac3sukjdrxzi-kv                                            Microsoft.KeyVault/vaults                           westus
  //  jac3sukjdrxzistgctmfunc                                     Microsoft.Storage/storageAccounts                   westus    Storage
  //  stgcrewtaskmgrauthfunc                                      Microsoft.Storage/storageAccounts                   westus2   Storage
  //  jac3sukjdrxzi-func-plan-CrewTaskMgrAuthSvcs                 Microsoft.Web/serverFarms                           westus    functionapp
  //  jac3sukjdrxzi-web-plan                                      Microsoft.Web/serverFarms                           westus    app
  //  WestUS2Plan                                                 Microsoft.Web/serverFarms                           westus2   functionapp
  //  jac3sukjdrxzi-func-CrewTaskMgrAuthSvcs                      Microsoft.Web/sites                                 westus    functionapp
  //  jac3sukjdrxzi-web                                           Microsoft.Web/sites                                 westus    app
  //  
  //  Process compilation finished
  //  