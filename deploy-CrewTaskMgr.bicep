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
   #WaitForBuildComplete
   echo "begin shutdown"
   #echo az functionapp delete --name jac3sukjdrxzi-func-CrewTaskMgrAuthSvcs --resource-group $rg
   #az functionapp delete --name jac3sukjdrxzi-func-CrewTaskMgrAuthSvcs --resource-group $rg
   #echo az storage account delete -n ${uniqueName}stgctmfunc -g $rg --yes
   #az storage account delete -n ${uniqueName}stgctmfunc -g $rg --yes
   #echo az apim delete --name ${uniqueName}-apim  --resource-group $rg --yes
   #az apim delete --name ${uniqueName}-apim  --resource-group $rg --yes
   #echo az apim list  --resource-group $rg
   #az apim list  --resource-group $rg
   #echo az apim deletedservice purge --service-name ${uniqueName}-apim --location $loc
   #az apim deletedservice purge --service-name ${uniqueName}-apim --location $loc
   #echo Previous shutdown/build is complete. Begin deployment build.
   echo az apim list  --resource-group $rg
   az apim list  --resource-group $rg
   echo az apim deletedservice purge --service-name ${uniqueName}-apim --location $loc
   az apim deletedservice purge --service-name ${uniqueName}-apim --location $loc
   echo az keyvault purge --name ${uniqueName}-kv --location $loc 
   az keyvault purge --name ${uniqueName}-kv --location $loc 
   echo az deployment group create --mode complete --template-file ./clear-resources.json --resource-group $rg
   az deployment group create --mode complete --template-file ./clear-resources.json --resource-group $rg
   #echo az group delete -g $rg  --yes 
   #az group delete -g $rg  --yes
   echo az apim list  --resource-group $rg
   az apim list  --resource-group $rg
   echo az apim deletedservice purge --service-name ${uniqueName}-apim --location $loc
   az apim deletedservice purge --service-name ${uniqueName}-apim --location $loc
   echo az keyvault purge --name ${uniqueName}-kv --location $loc 
   az keyvault purge --name ${uniqueName}-kv --location $loc 
   echo az deployment group create --name $name --resource-group $rg  --mode  Incremental  --template-file deploy-CrewTaskMgr.bicep  --parameters ownerId=$AZURE_OBJECTID  '@deploy.parameters.json' deployAPIM=false
   az deployment group create --name $name --resource-group $rg  --mode  Incremental  --template-file deploy-CrewTaskMgr.bicep  --parameters ownerId=$AZURE_OBJECTID  '@deploy.parameters.json' deployAPIM=false
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
   echo az apim list  --resource-group $rg
   az apim list  --resource-group $rg
   echo az apim deletedservice purge --service-name ${uniqueName}-apim --location $loc
   az apim deletedservice purge --service-name ${uniqueName}-apim --location $loc
   echo az keyvault purge --name ${uniqueName}-kv --location $loc 
   az keyvault purge --name ${uniqueName}-kv --location $loc 
   BuildIsComplete.exe
   az resource list -g $rg --query "[?resourceGroup=='$rg'].{ name: name, flavor: kind, resourceType: type, region: location }" --output table
   echo "showdown is complete"
   End commands to shut down this deployment using Azure CLI with bash

   emacs ESC 3 F10
   Begin commands for one time initializations using Azure CLI with bash
   az group delete --name $rg --yes
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
   Begin commands to deploy this file using Azure CLI with bash
   echo az deployment group create --name $name --resource-group $rg  --mode  Incremental  --template-file deploy-CrewTaskMgr.bicep  --parameters ownerId=$AZURE_OBJECTID  '@deploy.parameters.json' deployAPIM=true
   az deployment group create --name $name --resource-group $rg  --mode  Incremental  --template-file deploy-CrewTaskMgr.bicep  --parameters ownerId=$AZURE_OBJECTID  '@deploy.parameters.json' deployAPIM=true
   az resource list -g $rg --query "[?resourceGroup=='$rg'].{ name: name, flavor: kind, resourceType: type, region: location }" --output table
   End commands to deploy this file using Azure CLI with bash

   emacs ESC 5 F10
   Begin commands for one time initializations using Azure CLI with bash
   echo az apim  list --resource-group $rg 
   az apim list --resource-group $rg 
   echo az apim deletedservice list
   az apim deletedservice list
   End commands for one time initializations using Azure CLI with bash

   emacs ESC 6 F10
   Begin commands for one time initializations using Azure CLI with bash
   echo az apim delete --name ${uniqueName}-apim  --resource-group $rg --yes
   az apim delete --name ${uniqueName}-apim  --resource-group $rg --yes
   echo az apim deletedservice purge --service-name ${uniqueName}-apim --location $loc
   az apim deletedservice purge --service-name ${uniqueName}-apim --location $loc
   End commands for one time initializations using Azure CLI with bash

   emacs ESC 7 F10
   Begin commands for one time initializations using Azure CLI with bash
   echo az functionapp delete --name jac3sukjdrxzi-func-CrewTaskMgrAuthSvcs --resource-group $rg
   az functionapp delete --name jac3sukjdrxzi-func-CrewTaskMgrAuthSvcs --resource-group $rg
   End commands for one time initializations using Azure CLI with bash

   emacs ESC 8 F10
   Begin commands to deploy this file using Azure CLI with bash
   echo az deployment group create --name $name --resource-group $rg  --mode  Incremental  --template-file deploy-CrewTaskMgr.bicep  --parameters ownerId=$AZURE_OBJECTID  '@deploy.parameters.json' deployAPIM=true deployWeb=false deployFunctionApp=false useLocalBackendFunction=false
   az deployment group create --name $name --resource-group $rg  --mode  Incremental  --template-file deploy-CrewTaskMgr.bicep  --parameters ownerId=$AZURE_OBJECTID  '@deploy.parameters.json' deployAPIM=true deployWeb=false deployFunctionApp=false useLocalBackendFunction=false
   az resource list -g $rg --query "[?resourceGroup=='$rg'].{ name: name, flavor: kind, resourceType: type, region: location }" --output table
   End commands to deploy this file using Azure CLI with bash

   emacs ESC 9 F10
   Begin commands to deploy this file using Azure CLI with bash
   echo WaitForBuildComplete
   WaitForBuildComplete
   echo az deployment group create --name $name --resource-group $rg  --mode  Incremental  --template-file deploy-CrewTaskMgr.bicep  --parameters ownerId=$AZURE_OBJECTID  '@deploy.parameters.json' deployAPIM=true deployWeb=true deployFunctionApp=true useLocalBackendFunction=true
   az deployment group create --name $name --resource-group $rg  --mode  Incremental  --template-file deploy-CrewTaskMgr.bicep  --parameters ownerId=$AZURE_OBJECTID  '@deploy.parameters.json' deployAPIM=true deployWeb=true deployFunctionApp=true useLocalBackendFunction=true
   az resource list -g $rg --query "[?resourceGroup=='$rg'].{ name: name, flavor: kind, resourceType: type, region: location }" --output table
   End commands to deploy this file using Azure CLI with bash

   emacs ESC 10 F10
   Begin commands to deploy this file using Azure CLI with bash
   #echo WaitForBuildComplete
   #WaitForBuildComplete
   echo az deployment group create --mode complete --template-file ./clear-resources.json --resource-group $rg
   az deployment group create --mode complete --template-file ./clear-resources.json --resource-group $rg
   echo az apim deletedservice purge --service-name ${uniqueName}-apim --location $loc
   az apim deletedservice purge --service-name ${uniqueName}-apim --location $loc
   echo az keyvault purge --name ${uniqueName}-kv --location $loc 
   az keyvault purge --name ${uniqueName}-kv --location $loc 
   echo az deployment group create --name $name --resource-group $rg  --mode  Incremental  --template-file deploy-CrewTaskMgr.bicep  --parameters ownerId=$AZURE_OBJECTID  '@deploy.parameters.json' deployAPIM=true deployWeb=true deployFunctionApp=false useLocalBackendFunction=false
   az deployment group create --name $name --resource-group $rg  --mode  Incremental  --template-file deploy-CrewTaskMgr.bicep  --parameters ownerId=$AZURE_OBJECTID  '@deploy.parameters.json' deployAPIM=true deployWeb=true deployFunctionApp=false useLocalBackendFunction=false
   az resource list -g $rg --query "[?resourceGroup=='$rg'].{ name: name, flavor: kind, resourceType: type, region: location }" --output table
   End commands to deploy this file using Azure CLI with bash

 */

@description('Deploy the APIM')
param deployAPIM bool = false
output deployAPIM bool = deployAPIM

@description('Deploy the Web Site')
param deployWeb bool = false
output deployWeb bool = deployWeb

@description('deploy FunctionApp')
param deployFunctionApp bool = false
output deployFunctionApp bool = deployFunctionApp

@description('Reference Backend Function')
param useLocalBackendFunction bool = false
output useLocalBackendFunction bool = useLocalBackendFunction

@description('Rquire Azure AD authentication for Azure Func CrewTaskMgrAuthSvs')
param requireAuthentication bool = true

@description('Location of the Authenticated Function App')
param locCrewTaskMgrAuthFuncApp string = 'westu2'

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

// begin function app

param funcCrewTaskMgrAuthSvcsName string = 'CrewTaskMgrAuthSvcs'

@description('The URL for the GitHub repository that contains the project to deploy.')
param repoURL string = 'https://github.com/siegfried01/HelloAzureADAuthenticatedFunc.git'

@description('The branch of the GitHub repository to use.')
param branch string = 'master'

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

// https://learn.microsoft.com/en-us/azure/azure-functions/functions-infrastructure-as-code?tabs=bicep

param storageAccountName string = '${name}stgctmfunc'
resource stgCrewTaskMgrAuthFunc 'Microsoft.Storage/storageAccounts@2022-05-01' = {
    name: storageAccountName
    location: location
    sku: {
        name: 'Standard_LRS'
    }
    kind: 'StorageV2'

    properties: {
        supportsHttpsTrafficOnly: true
        defaultToOAuthAuthentication: true
    }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2021-09-01' existing = {
    name: 'default'
    parent: stgCrewTaskMgrAuthFunc
}

param myLogAnalyticsId string = '/subscriptions/acc26051-92a5-4ed1-a226-64a187bc27db/resourcegroups/defaultresourcegroup-wus2/providers/microsoft.operationalinsights/workspaces/defaultworkspace-acc26051-92a5-4ed1-a226-64a187bc27db-wus2'
//resource myLogAnalytics 'Microsoft.OperationalInsights/workspaces@2021-12-01-preview' existing = {
//    name: '${name}-LogAnalytics'

//Id: '/subscriptions/acc26051-92a5-4ed1-a226-64a187bc27db/resourcegroups/defaultresourcegroup-wus2/providers/microsoft.operationalinsights/workspaces/defaultworkspace-acc26051-92a5-4ed1-a226-64a187bc27db-wus2'
//}
resource storageDataPlaneLogs 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
    name: '${storageAccountName}-logs'
    scope: blobService
    properties: {
        workspaceId: myLogAnalyticsId //myLogAnalytics.id
        logs: [
            {
                category: 'StorageWrite'
                enabled: true
            }
        ]
        metrics: [
            {
                category: 'Transaction'
                enabled: true
            }
        ]
    }
}
resource applicationInsights 'Microsoft.Insights/components@2020-02-02' = {
    name: '${name}-appins'
    location: location
    kind: 'web'
    properties: {
        Application_Type: 'web'
        Request_Source: 'IbizaWebAppExtensionCreate'
    }
}

var blobStorageConnectionString = 'DefaultEndpointsProtocol=https;AccountName=${storageAccountName};AccountKey=${stgCrewTaskMgrAuthFunc.listKeys().keys[0].value}'

resource funcCrewTaskMgrAuthSvcs 'Microsoft.Web/sites@2022-09-01' = if (deployFunctionApp) {
    name: '${name}-func-CrewTaskMgrAuthSvcs'
    location: locCrewTaskMgrAuthFuncApp
    kind: 'functionapp'
    identity: {
        type: 'SystemAssigned'
    }
    properties: {
        clientAffinityEnabled: false
        httpsOnly: true
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
            windowsFxVersion: 'DOTNETCORE|6'
            numberOfWorkers: 1
            acrUseManagedIdentityCreds: false
            alwaysOn: false
            http20Enabled: false
            functionAppScaleLimit: 200
            minimumElasticInstanceCount: 0
        }
        scmSiteAlsoStopped: false
        clientCertEnabled: false
        clientCertMode: 'Required'
        hostNamesDisabled: false
        containerSize: 1536
        dailyMemoryTimeQuota: 0
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
            //'APPLICATIONINSIGHTS_CONNECTION_STRING': ApplicationInsights_ConnectionString
            'APPINSIGHTS_INSTRUMENTATIONKEY': applicationInsights.properties.InstrumentationKey
            'FUNCTIONS_WORKER_RUNTIME': 'dotnet'
            'Logging:ApplicationInsights:Enabled': 'true'
            'Logging:ApplicationInsights:LogLevel': 'Trace'
            'Logging:LogLevel:Default': 'Trace'
            'Logging.LogLevel:Microsoft': 'Trace'
            'ASPNETCORE_ENVIRONMENT': 'Development'
            'MICROSOFT_PROVIDER_AUTHENTICATION_SECRET': '${BackEndClientSecret}'
            'AzureWebJobsStorage': blobStorageConnectionString
        }
    }
    // resource sites_CrewTaskMgrAuthenticatedSvcs_name_Hello 'functions@2022-09-01' = {
    //     name: 'Hello'
    //     properties: {
    //         script_root_path_href: 'https://${funcCrewTaskMgrAuthSvcsName}.azurewebsites.net/admin/vfs/site/wwwroot/Hello/'
    //         script_href: 'https://${funcCrewTaskMgrAuthSvcsName}.azurewebsites.net/admin/vfs/site/wwwroot/bin/CrewTaskMgrAuthenticatedServices.dll'
    //         config_href: 'https://${funcCrewTaskMgrAuthSvcsName}.azurewebsites.net/admin/vfs/site/wwwroot/Hello/function.json'
    //         test_data_href: 'https://${funcCrewTaskMgrAuthSvcsName}.azurewebsites.net/admin/vfs/data/Functions/sampledata/Hello.dat'
    //         href: 'https://${funcCrewTaskMgrAuthSvcsName}.azurewebsites.net/admin/functions/Hello'
    //         config: {}
    //         invoke_url_template: 'https://${funcCrewTaskMgrAuthSvcsName}.azurewebsites.net/api/hello'
    //         language: 'DotNetAssembly'
    //         isDisabled: false
    //     }
    // }

    resource siteName_web 'sourcecontrols@2020-12-01' = {
        name: 'web'
        properties: {
            repoUrl: repoURL
            branch: branch
            isManualIntegration: true
        }
    }
}

// end function app

resource webHostingPlan 'Microsoft.Web/serverfarms@2020-12-01' = if (deployWeb) {
    name: '${name}-web-plan'
    location: location
    sku: {
        name: webPlanSku
        tier: 'Free'
        size: webPlanSku
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

resource website 'Microsoft.Web/sites@2022-09-01' = if (deployWeb) {
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

    resource sites_CTMBlazorSvrClient20230409134317_name_web 'config@2022-09-01' = {
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

    resource sites_CTMBlazorSvrClient20230409134317_name_sites_CTMBlazorSvrClient20230409134317_name_azurewebsites_net 'hostNameBindings@2022-09-01' = {

        name: '${website.name}.azurewebsites.net'
        properties: {
            siteName: 'CTMBlazorSvrClient20230409134317'
            hostNameType: 'Verified'
        }
    }

    resource sites_CTMBlazorSvrClient20230409134317_name_Microsoft_AspNetCore_AzureAppServices_SiteExtension 'siteextensions@2022-09-01' = {

        name: 'Microsoft.AspNetCore.AzureAppServices.SiteExtension'
    }
}

// Output our variable

output blobStorageConnectionString string = blobStorageConnectionString

// https://stackoverflow.com/questions/75544346/how-can-i-get-azure-functions-keys-from-bicep
//var funcKey = listkeys(concat(resourceId('Microsoft.Web/sites', funcCrewTaskMgrAuthSvcs), '/host/default/'),'2021-02-01').masterKey.value
//var fk = funcCrewTaskMgrAuthSvcs.listkeys().keys[0]
// var funcKey = listkeys('${funcCrewTaskMgrAuthSvcs.id}/host/default', '2022-03-01').masterKey[0].value

resource funcCrewTaskMgrAuthSvcsOther 'Microsoft.Web/sites@2022-09-01' existing = if (!useLocalBackendFunction) {
    name: 'zbckw6q67sgh2-func-CrewTaskMgrAuthSvcs'
    scope: resourceGroup('rg_AuthFuncSourceControl')
}
var appFunctionId = useLocalBackendFunction ? '${funcCrewTaskMgrAuthSvcs.id}/host/default' : '${funcCrewTaskMgrAuthSvcsOther.id}/host/default'

// https://stackoverflow.com/questions/69251430/output-newly-created-function-app-key-using-bicep
var defaultHostKey = listkeys(appFunctionId, '2016-08-01').functionKeys.default

output defaultAppFunctionKey string = defaultHostKey

param components_appinsCrewTaskMgrAuthenticatedServices_externalid string = '/subscriptions/acc26051-92a5-4ed1-a226-64a187bc27db/resourceGroups/rg_CrewTaskMgr/providers/microsoft.insights/components/appinsCrewTaskMgrAuthenticatedServices'
param apimCrewTaskMgtName string = '${name}-apim'

resource service_jac3sukjdrxzi_apim_name_resource 'Microsoft.ApiManagement/service@2022-09-01-preview' = if (deployAPIM) {
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
    dependsOn: [
        funcCrewTaskMgrAuthSvcs
    ]
    // resource service_jac3sukjdrxzi_apim_name_zbckw6q67sgh2_func_crewtaskmgrauthsvcs_get_hello 'operations@2022-09-01-preview' = {
    //     name: 'get-hello'
    //     properties: {
    //         displayName: 'Hello'
    //         method: 'GET'
    //         urlTemplate: '/Hello'
    //         templateParameters: []
    //         responses: []
    //     }
    //     resource service_jac3sukjdrxzi_apim_name_zbckw6q67sgh2_func_crewtaskmgrauthsvcs_get_hello_policy 'policies@2022-09-01-preview' = {
    //         name: 'policy'
    //         properties: {
    //             value: '<policies>\r\n  <inbound>\r\n    <base />\r\n    <set-backend-service id="apim-generated-policy" backend-id="${name}-func-crewtaskmgrauthsvcs" />\r\n  </inbound>\r\n  <backend>\r\n    <base />\r\n  </backend>\r\n  <outbound>\r\n    <base />\r\n  </outbound>\r\n  <on-error>\r\n    <base />\r\n  </on-error>\r\n</policies>'
    //             format: 'xml'
    //         }
    //     }
    // }

    // resource service_jac3sukjdrxzi_apim_name_zbckw6q67sgh2_func_crewtaskmgrauthsvcs_post_hello 'operations@2022-09-01-preview' = {
    //     name: 'post-hello'
    //     properties: {
    //         displayName: 'Hello'
    //         method: 'POST'
    //         urlTemplate: '/Hello'
    //         templateParameters: []
    //         responses: []
    //     }
    //     resource service_jac3sukjdrxzi_apim_name_zbckw6q67sgh2_func_crewtaskmgrauthsvcs_post_hello_policy 'policies@2022-09-01-preview' = {
    //         name: 'policy'
    //         properties: {
    //             value: '<policies>\r\n  <inbound>\r\n    <base />\r\n    <set-backend-service id="apim-generated-policy" backend-id="${name}-func-crewtaskmgrauthsvcs" />\r\n  </inbound>\r\n  <backend>\r\n    <base />\r\n  </backend>\r\n  <outbound>\r\n    <base />\r\n  </outbound>\r\n  <on-error>\r\n    <base />\r\n  </on-error>\r\n</policies>'
    //             format: 'xml'
    //         }
    //     }
    // }
    resource service_jac3sukjdrxzi_apim_name_zbckw6q67sgh2_func_crewtaskmgrauthsvcs 'apis@2022-09-01-preview' = {
        // name: '${name}-api-func-crewtaskmgrauthsvcs'
        name: 'zbckw6q67sgh2-func-crewtaskmgrauthsvcs'
        properties: {
            //displayName: '${name}-api-func-CrewTaskMgrAuthSvcs'
            displayName: 'zbckw6q67sgh2-func-CrewTaskMgrAuthSvcs'
            apiRevision: '1'
            description: 'Import from "${name}-func-CrewTaskMgrAuthSvcs" Function App'
            subscriptionRequired: true
            //path: '${name}-func-CrewTaskMgrAuthSvcs'
            path: 'zbckw6q67sgh2-func-CrewTaskMgrAuthSvcs'
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
    }
    /*
    resource Microsoft_ApiManagement_service_backends_service_jac3sukjdrxzi_apim_name_zbckw6q67sgh2_func_crewtaskmgrauthsvcs 'backends@2022-09-01-preview' = {
        name: 'zbckw6q67sgh2-func-crewtaskmgrauthsvcs'
        //name: '${name}-backend-func-crewtaskmgrauthsvcs'
        properties: {
            //description: '${name}-backend-func-CrewTaskMgrAuthSvcs'
            description: 'zbckw6q67sgh2-func-CrewTaskMgrAuthSvcs'
            //url: 'https://${name}-func-crewtaskmgrauthsvcs.azurewebsites.net/api'
            url: 'https://zbckw6q67sgh2-func-crewtaskmgrauthsvcs.azurewebsites.net/api'
            protocol: 'http'
            // {"code":"ValidationError","message":"One or more fields contain incorrect values:","details":[{"code":"ValidationError","target":"resourceId","message":"Value should represent absolute http URL"}]}
            //resourceId:  funcCrewTaskMgrAuthSvcsOther.id //'/subscriptions/acc26051-92a5-4ed1-a226-64a187bc27db/resourceGroups/rg_AuthFuncSourceControl/providers/Microsoft.Web/sites/zbckw6q67sgh2-func-CrewTaskMgrAuthSvcs'
            //resourceId: (useLocalBackendFunction ? '/subscriptions/acc26051-92a5-4ed1-a226-64a187bc27db/resourceGroups/rg_CrewTaskMgr/providers/Microsoft.Web/sites/jac3sukjdrxzi-func-CrewTaskMgrAuthSvcs' : '/subscriptions/acc26051-92a5-4ed1-a226-64a187bc27db/resourceGroups/rg_AuthFuncSourceControl/providers/Microsoft.Web/sites/zbckw6q67sgh2-func-CrewTaskMgrAuthSvcs' )
            resourceId: 'https://management.azure.com/subscriptions/acc26051-92a5-4ed1-a226-64a187bc27db/resourceGroups/rg_AuthFuncSourceControl/providers/Microsoft.Web/sites/zbckw6q67sgh2-func-CrewTaskMgrAuthSvcs'
            credentials: {
                header: {
                    'x-functions-key': [
                        //'{{${name}-func-crewtaskmgrauthsvcs-key}}'
                        '{{zbckw6q67sgh2-func-crewtaskmgrauthsvcs-key}}'
                    ]
                }
            }
        }
    }
 */

    resource Microsoft_ApiManagement_service_backends_service_jac3sukjdrxzi_apim_name_zbckw6q67sgh2_func_crewtaskmgrauthsvcs 'backends@2022-09-01-preview' = {
        name: 'zbckw6q67sgh2-func-crewtaskmgrauthsvcs'
        properties: {
            description: 'zbckw6q67sgh2-func-CrewTaskMgrAuthSvcs'
            url: 'https://zbckw6q67sgh2-func-crewtaskmgrauthsvcs.azurewebsites.net/api'
            protocol: 'http'
            resourceId: 'https://management.azure.com/subscriptions/acc26051-92a5-4ed1-a226-64a187bc27db/resourceGroups/rg_AuthFuncSourceControl/providers/Microsoft.Web/sites/zbckw6q67sgh2-func-CrewTaskMgrAuthSvcs'
            credentials: {
                header: {
                    'x-functions-key': [
                        '{{zbckw6q67sgh2-func-crewtaskmgrauthsvcs-key}}'
                    ]
                }
            }
        }
    }

    // resource service_jac3sukjdrxzi_apim_name_644aea511aff160ccc6b04cc 'namedValues@2022-09-01-preview' = {
    //     name: '644aea511aff160ccc6b04cc'
    //     properties: {
    //         displayName: 'Logger-Credentials--644aea511aff160ccc6b04cd'
    //         secret: true
    //     }
    // }
    // resource service_jac3sukjdrxzi_apim_name_crewtaskmgrauthenticatedsvcs_key 'namedValues@2022-09-01-preview' = {
    //     name: 'crewtaskmgrauthenticatedsvcs-key'
    //     properties: {
    //         displayName: 'crewtaskmgrauthenticatedsvcs-key'
    //         tags: [
    //             'key'
    //             'function'
    //             'auto'
    //         ]
    //         secret: true
    //     }
    // }

    // this is causing error : {"code":"ValidationError","message":"One or more fields contain incorrect values:","details":[{"code":"ValidationError","target":"value","message":"Either Value or Keyvault must be provided."}]} probably because it cannot find the property
    resource service_jac3sukjdrxzi_apim_name_zbckw6q67sgh2_func_crewtaskmgrauthsvcs_key 'namedValues@2022-09-01-preview' = {
        //  name: '${name}-func-crewtaskmgrauthsvcs-key'
        name: 'zbckw6q67sgh2-func-crewtaskmgrauthsvcs-key'
        properties: {
            //displayName: '${name}-func-crewtaskmgrauthsvcs-key'
            displayName: 'zbckw6q67sgh2-func-crewtaskmgrauthsvcs-key'
            tags: [
                'key'
                'function'
                'auto'
            ]
            secret: true
        }
    }

    /*
    resource Microsoft_ApiManagement_service_properties_service_jac3sukjdrxzi_apim_name_zbckw6q67sgh2_func_crewtaskmgrauthsvcs_key 'properties@2019-01-01' = {
        // name: '${name}-func-crewtaskmgrauthsvcs-key'
        name: 'zbckw6q67sgh2-func-crewtaskmgrauthsvcs-key'
        properties: {
            // displayName: '${name}-func-crewtaskmgrauthsvcs-key'
            displayName: 'zbckw6q67sgh2-func-crewtaskmgrauthsvcs-key'
            value: '5OCr/8M/top-secret-passwsord==' //defaultHostKey 
            tags: [
                'key'
                'function'
                'auto'
            ]
            secret: true
        }
    }
    */
    resource service_jac3sukjdrxzi_apim_name_policy 'policies@2022-09-01-preview' = {
        name: 'policy'
        properties: {
            value: '<!--\r\n    IMPORTANT:\r\n    - Policy elements can appear only within the <inbound>, <outbound>, <backend> section elements.\r\n    - Only the <forward-request> policy element can appear within the <backend> section element.\r\n    - To apply a policy to the incoming request (before it is forwarded to the backend service), place a corresponding policy element within the <inbound> section element.\r\n    - To apply a policy to the outgoing response (before it is sent back to the caller), place a corresponding policy element within the <outbound> section element.\r\n    - To add a policy position the cursor at the desired insertion point and click on the round button associated with the policy.\r\n    - To remove a policy, delete the corresponding policy statement from the policy document.\r\n    - Policies are applied in the order of their appearance, from the top down.\r\n-->\r\n<policies>\r\n  <inbound>\r\n    <cors allow-credentials="true">\r\n      <allowed-origins>\r\n        <origin>https://stgstaticwebprotectapim.z5.web.core.windows.net</origin>\r\n        <origin>https://jac3sukjdrxzi-web.azurewebsites.net</origin>\r\n      </allowed-origins>\r\n      <allowed-methods preflight-result-max-age="120">\r\n        <method>GET</method>\r\n      </allowed-methods>\r\n      <allowed-headers>\r\n        <header>*</header>\r\n      </allowed-headers>\r\n      <expose-headers>\r\n        <header>*</header>\r\n      </expose-headers>\r\n    </cors>\r\n    <validate-jwt header-name="Authorization" failed-validation-httpcode="401" failed-validation-error-message="Unauthorized. Access token is missing or invalid." require-expiration-time="true" require-signed-tokens="true" clock-skew="300">\r\n      <openid-config url="https://enterprisedemoorg.b2clogin.com/enterprisedemoorg.onmicrosoft.com/v2.0/.well-known/openid-configuration?p=B2C_1_Frontend_APIM_Totorial_SUSI" />\r\n      <required-claims>\r\n        <claim name="aud">\r\n          <value>0edb71aa-18a3-46d3-a3ee-6271489bd312</value>\r\n        </claim>\r\n      </required-claims>\r\n    </validate-jwt>\r\n  </inbound>\r\n  <backend>\r\n    <forward-request />\r\n  </backend>\r\n  <outbound />\r\n  <on-error />\r\n</policies>'
            format: 'xml'
        }
    }
    resource service_jac3sukjdrxzi_apim_name_unlimited 'products@2022-09-01-preview' = {
        name: 'unlimited'
        properties: {
            displayName: 'Unlimited'
            description: 'unlimited'
            subscriptionRequired: false
            state: 'notPublished'
        }
        resource service_jac3sukjdrxzi_apim_name_unlimited_zbckw6q67sgh2_func_crewtaskmgrauthsvcs 'apis@2022-09-01-preview' = {
            //name: '${name}-func-crewtaskmgrauthsvcs'
            name: 'zbckw6q67sgh2-func-crewtaskmgrauthsvcs'

        }

        // resource service_jac3sukjdrxzi_apim_name_unlimited_646c13b23a838a1df4462c9d 'groupLinks@2022-09-01-preview' = {
        //     name: '646c13b23a838a1df4462c9d'
        //     properties: {
        //         groupId: '${service_jac3sukjdrxzi_apim_name_resource.id}/groups/administrators'
        //     }
        // }

        // resource service_jac3sukjdrxzi_apim_name_unlimited_646c3351a578e906b80f08b7 'apiLinks@2022-09-01-preview' = {
        //     name: '646c3351a578e906b80f08b7'
        //     properties: {
        //         apiId: service_jac3sukjdrxzi_apim_name_zbckw6q67sgh2_func_crewtaskmgrauthsvcs.id
        //     }
        // }
    }
    // resource Microsoft_ApiManagement_service_properties_service_jac3sukjdrxzi_apim_name_644aea511aff160ccc6b04cc 'properties@2019-01-01' = {
    //     name: '644aea511aff160ccc6b04cc'
    //     properties: {
    //         displayName: 'Logger-Credentials--644aea511aff160ccc6b04cd'
    //         value: 'c71b3ac4-9f20-4465-9963-0737c42218a0'
    //         secret: true
    //     }
    // }
    // resource Microsoft_ApiManagement_service_properties_service_jac3sukjdrxzi_apim_name_crewtaskmgrauthenticatedsvcs_key 'properties@2019-01-01' = {
    //     name: 'crewtaskmgrauthenticatedsvcs-key'
    //     properties: {
    //         displayName: 'crewtaskmgrauthenticatedsvcs-key'
    //         value: 'i-aZx0ei-uVAOcfFO9tQBKK0WlYS2Q-E3VyuETG32Tz8AzFuWsftpg=='
    //         tags: [
    //             'key'
    //             'function'
    //             'auto'
    //         ]
    //         secret: true
    //     }
    // }

    // resource service_jac3sukjdrxzi_apim_name_master 'subscriptions@2022-09-01-preview' = {
    //     name: 'master'
    //     properties: {
    //         scope: '${service_jac3sukjdrxzi_apim_name_resource.id}/'
    //         displayName: 'Built-in all-access subscription'
    //         state: 'active'
    //         allowTracing: false
    //     }
    // }
}
resource Microsoft_ApiManagement_service_properties_service_jac3sukjdrxzi_apim_name_zbckw6q67sgh2_func_crewtaskmgrauthsvcs_key 'Microsoft.ApiManagement/service/properties@2019-01-01' = {
  parent: service_jac3sukjdrxzi_apim_name_resource
  name: 'zbckw6q67sgh2-func-crewtaskmgrauthsvcs-key'
  properties: {
    displayName: 'zbckw6q67sgh2-func-crewtaskmgrauthsvcs-key'
    value: '5OCr/8M/top-secret-passwsord=='
    tags: [
      'key'
      'function'
      'auto'
    ]
    secret: true
  }
}
