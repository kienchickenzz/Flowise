import { NextFunction, Request, Response } from 'express'
import { StatusCodes } from 'http-status-codes'
import { LoginMethodErrorMessage, LoginMethodService } from '../services/login-method.service'
import { getRunningExpressApp } from '../../utils/getRunningExpressApp'
import { LoginMethod, LoginMethodStatus } from '../database/entities/login-method.entity'
import { InternalFlowiseError } from '../../errors/internalFlowiseError'
import { decrypt } from '../utils/encryption.util'
import AzureSSO from '../sso/AzureSSO'
import GoogleSSO from '../sso/GoogleSSO'
import Auth0SSO from '../sso/Auth0SSO'
import { OrganizationService } from '../services/organization.service'
import { Platform } from '../../Interface'
import GithubSSO from '../sso/GithubSSO'
import KeyCloakSSO from '../sso/KeyCloakSSO'
import logger from '../../utils/logger'

export class LoginMethodController {
    public async create(req: Request, res: Response, next: NextFunction) {
        try {
            const loginMethodService = new LoginMethodService()
            const loginMethod = await loginMethodService.createLoginMethod(req.body)
            return res.status(StatusCodes.CREATED).json(loginMethod)
        } catch (error) {
            next(error)
        }
    }

    public async defaultMethods(req: Request, res: Response, next: NextFunction) {
        let queryRunner
        try {
            queryRunner = getRunningExpressApp().AppDataSource.createQueryRunner()
            await queryRunner.connect()
            let organizationId
            const platformType = getRunningExpressApp().identityManager.getPlatformType()
            logger.debug('Platform type:', platformType)
            
            if (platformType === Platform.CLOUD || platformType === Platform.OPEN_SOURCE) {
                organizationId = undefined
            } else if (platformType === Platform.ENTERPRISE) {
                const organizationService = new OrganizationService()
                const organizations = await organizationService.readOrganization(queryRunner)
                if (organizations.length > 0) {
                    organizationId = organizations[0].id
                } else {
                    return res.status(StatusCodes.OK).json({})
                }
            } else {
                return res.status(StatusCodes.OK).json({})
            }
            
            logger.debug(`OrganizationId: ${organizationId}`)
            const loginMethodService = new LoginMethodService()

            const providers: string[] = []

            let loginMethod = await loginMethodService.readLoginMethodByOrganizationId(organizationId, queryRunner)
            logger.debug(`Found login methods: ${loginMethod?.length || 0}`)
            
            if (loginMethod) {
                for (let method of loginMethod) {
                    logger.debug(`Method: ${method.name}, Status: ${method.status}, Expected: ${LoginMethodStatus.ENABLE}`)
                    if (method.status === LoginMethodStatus.ENABLE) {
                        providers.push(method.name)
                        logger.debug(`Added provider: ${method.name}`)
                    }
                }
            }
            logger.debug(`Final providers: ${JSON.stringify(providers)}`)
            return res.status(StatusCodes.OK).json({ providers: providers })
        } catch (error) {
            next(error)
        } finally {
            if (queryRunner) await queryRunner.release()
        }
    }

    public async read(req: Request, res: Response, next: NextFunction) {
        let queryRunner
        try {
            queryRunner = getRunningExpressApp().AppDataSource.createQueryRunner()
            await queryRunner.connect()
            const query = req.query as Partial<LoginMethod>
            const loginMethodService = new LoginMethodService()

            const loginMethodConfig = {
                providers: [],
                callbacks: [
                    { providerName: 'azure', callbackURL: AzureSSO.getCallbackURL() },
                    { providerName: 'google', callbackURL: GoogleSSO.getCallbackURL() },
                    { providerName: 'auth0', callbackURL: Auth0SSO.getCallbackURL() },
                    { providerName: 'github', callbackURL: GithubSSO.getCallbackURL() },
                    { providerName: 'keycloak', callbackURL: KeyCloakSSO.getCallbackURL() }
                ]
            }
            let loginMethod: any
            if (query.id) {
                loginMethod = await loginMethodService.readLoginMethodById(query.id, queryRunner)
                if (!loginMethod) throw new InternalFlowiseError(StatusCodes.NOT_FOUND, LoginMethodErrorMessage.LOGIN_METHOD_NOT_FOUND)
                loginMethod.config = JSON.parse(await decrypt(loginMethod.config))
            } else {
                loginMethod = await loginMethodService.readLoginMethodByOrganizationId(query.organizationId, queryRunner)

                for (let method of loginMethod) {
                    method.config = JSON.parse(await decrypt(method.config))
                }
                loginMethodConfig.providers = loginMethod
            }
            return res.status(StatusCodes.OK).json(loginMethodConfig)
        } catch (error) {
            next(error)
        } finally {
            if (queryRunner) await queryRunner.release()
        }
    }
    public async update(req: Request, res: Response, next: NextFunction) {
        try {
            const loginMethodService = new LoginMethodService()
            const loginMethod = await loginMethodService.createOrUpdateConfig(req.body)
            if (loginMethod?.status === 'OK' && loginMethod?.organizationId) {
                const appServer = getRunningExpressApp()
                let providers: any[] = req.body.providers
                providers.map((provider: any) => {
                    const identityManager = appServer.identityManager
                    if (provider.config.clientID) {
                        provider.config.configEnabled = provider.status === LoginMethodStatus.ENABLE
                        identityManager.initializeSsoProvider(appServer.app, provider.providerName, provider.config)
                    }
                })
            }
            return res.status(StatusCodes.OK).json(loginMethod)
        } catch (error) {
            next(error)
        }
    }
    public async testConfig(req: Request, res: Response, next: NextFunction) {
        try {
            const providers = req.body.providers
            if (req.body.providerName === 'azure') {
                const response = await AzureSSO.testSetup(providers[0].config)
                return res.json(response)
            } else if (req.body.providerName === 'google') {
                const response = await GoogleSSO.testSetup(providers[0].config)
                return res.json(response)
            } else if (req.body.providerName === 'auth0') {
                const response = await Auth0SSO.testSetup(providers[0].config)
                return res.json(response)
            } else if (req.body.providerName === 'github') {
                const response = await GithubSSO.testSetup(providers[0].config)
                return res.json(response)
            } else if (req.body.providerName === 'keycloak') {
                const response = await KeyCloakSSO.testSetup(providers[0].config)
                return res.json(response)
            } else {
                return res.json({ error: 'Provider not supported' })
            }
        } catch (error) {
            next(error)
        }
    }
}
