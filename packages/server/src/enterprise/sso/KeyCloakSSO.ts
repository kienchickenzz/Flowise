import SSOBase from './SSOBase'
import passport from 'passport'
import { Profile, Strategy as OpenIDConnectStrategy, VerifyCallback } from 'passport-openidconnect'
import auditService from '../services/audit'
import { ErrorMessage, LoggedInUser, LoginActivityCode } from '../Interface.Enterprise'
import { setTokenOrCookies } from '../middleware/passport'
import axios from 'axios'
import logger from '../../utils/logger'
// import Request from 'express'

const PROVIDER_NAME_KEYCLOAK_SSO = 'Keycloak SSO'

class KeycloakSSO extends SSOBase {
    static LOGIN_URI = '/api/v1/keycloak/login'
    static CALLBACK_URI = '/api/v1/keycloak/callback'
    static LOGOUT_URI = '/api/v1/keycloak/logout'

    getProviderName(): string {
        return PROVIDER_NAME_KEYCLOAK_SSO
    }

    static getCallbackURL(): string {
        const APP_URL = process.env.APP_URL || 'http://127.0.0.1:' + process.env.PORT
        return APP_URL + KeycloakSSO.CALLBACK_URI
    }

    setSSOConfig( ssoConfig: any ) {
        super.setSSOConfig( ssoConfig )

        logger.debug( `setSSOConfig called with: ${JSON.stringify(ssoConfig, null, 2)}`)

        if ( ssoConfig ) {
            const { issuer, clientID, clientSecret, authorizationURL, tokenURL, userInfoURL } = this.ssoConfig

            logger.debug( KeycloakSSO.getCallbackURL() )

            passport.use(
                'keycloak',
                new OpenIDConnectStrategy(
                    {
                        issuer: issuer || 'http://localhost:8080/realms/flowise-realm',
                        
                        // These are the client credentials you configured in Keycloak
                        clientID: clientID || 'your_keycloak_client_id',
                        clientSecret: clientSecret || 'your_keycloak_client_secret',
                        
                        // The callback URL where Keycloak will send users after authentication
                        callbackURL: KeycloakSSO.getCallbackURL(),
                        
                        authorizationURL: authorizationURL || undefined,
                        tokenURL: tokenURL || undefined,
                        userInfoURL: userInfoURL || undefined,
                        
                        // This allows us to access the request object in our verification function
                        // which is useful for logging and session management
                        passReqToCallback: true,
                        
                        scope: 'openid profile email'
                    },
                    this.handleKeycloakCallback.bind( this ) as any,
                )
            )
        } else {
            // If no config is provided, remove the strategy to prevent errors
            passport.unuse( 'keycloak' )
        }
    }

    /**
     * Initializes the Keycloak SSO routes and middleware
     * This method sets up the Express.js routes that handle the OAuth2 flow
     */
    initialize() {
        this.setSSOConfig( this.ssoConfig )

        // Route 1: Initiate login - redirects user to Keycloak login page
        // When user clicks "Login with Keycloak", they'll be sent to this endpoint
        this.app.get(KeycloakSSO.LOGIN_URI, (req, res, next?) => {
            if (!this.getSSOConfig()) {
                return res.status(400).json({ error: 'Keycloak SSO is not configured.' })
            }
            
            // Passport will automatically redirect the user to Keycloak's authorization endpoint
            // with the proper parameters (client_id, redirect_uri, scope, etc.)
            passport.authenticate('keycloak', {
                scope: 'openid profile email' // Request these scopes for user information
            })(req, res, next)
        })

        // Route 2: Handle callback from Keycloak after user authentication
        // Keycloak will redirect users here with an authorization code
        this.app.get(KeycloakSSO.CALLBACK_URI, (req, res, next?) => {
            if (!this.getSSOConfig()) {
                return res.status(400).json({ error: 'Keycloak SSO is not configured.' })
            }
            
            // Passport will automatically:
            // 1. Extract the authorization code from the URL
            // 2. Exchange it for access and refresh tokens
            // 3. Fetch user profile information
            // 4. Call our verification callback function
            passport.authenticate('keycloak', async (err: any, user: LoggedInUser) => {
                try {
                    if (err || !user) {
                        if (err?.name == 'SSO_LOGIN_FAILED') {
                            // Redirect to login page with error message for user-friendly display
                            const error = { message: err.message }
                            const signinUrl = `/signin?error=${encodeURIComponent(JSON.stringify(error))}`
                            return res.redirect(signinUrl)
                        }
                        return next ? next(err) : res.status(401).json(err)
                    }
                    
                    // Login successful - establish user session
                    req.login(user, { session: true }, async (error) => {
                        if (error) return next ? next(error) : res.status(401).json(error)
                        
                        // Set authentication tokens/cookies and redirect to application
                        return setTokenOrCookies(res, user, true, req, true, true)
                    })
                } catch (error) {
                    return next ? next(error) : res.status(401).json(error)
                }
            })(req, res, next)
        })
    }

    /**
     * Test method to validate Keycloak configuration
     * This method attempts to connect to Keycloak to verify that the configuration is correct
     * It's useful for admin interfaces to test SSO setup before enabling it for users
     */
    static async testSetup(ssoConfig: any) {
        const { issuer, clientID, clientSecret } = ssoConfig

        try {
            // Test connectivity by fetching the OpenID Connect discovery document
            // This endpoint should be publicly accessible and doesn't require authentication
            const discoveryUrl = issuer + '/.well-known/openid-connect-configuration'
            const discoveryResponse = await axios.get(discoveryUrl, {
                timeout: 5000, // 5 second timeout
                headers: { 'Accept': 'application/json' }
            })
            
            if (discoveryResponse.status === 200) {
                // Optionally, we could also test client credentials by attempting to get a token
                // but discovery endpoint test is usually sufficient to verify basic connectivity
                return { message: 'Keycloak configuration test successful' }
            }
            
            return { error: 'Keycloak discovery endpoint returned unexpected status' }
        } catch (error) {
            const errorMessage = 'Keycloak Configuration test failed. Please check your issuer URL and network connectivity.'
            return { error: errorMessage }
        }
    }

    /**
     * Refreshes the access token using the refresh token
     * This method is called when the current access token expires
     * It exchanges the refresh token for a new access token
     */
    async refreshToken(ssoRefreshToken: string) {
        const { issuer, clientID, clientSecret } = this.ssoConfig

        try {
            // Construct the token endpoint URL from the issuer
            const tokenEndpoint = issuer + '/protocol/openid-connect/token'
            
            // Make a request to exchange refresh token for new access token
            const response = await axios.post(
                tokenEndpoint,
                {
                    client_id: clientID,
                    client_secret: clientSecret,
                    grant_type: 'refresh_token',
                    refresh_token: ssoRefreshToken
                },
                {
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    timeout: 5000 // 5 second timeout
                }
            )
            
            // Return the new tokens (access_token, refresh_token, etc.)
            return { ...response.data }
        } catch (error) {
            const errorMessage = 'Failed to refresh token from Keycloak.'
            return { error: errorMessage }
        }
    }

    /**
     * Handle logout - optional method to implement single logout
     * This could be called to notify Keycloak when user logs out from Flowise
     * to maintain session consistency across all applications
     */
    async logout(ssoAccessToken: string) {
        const { issuer, clientID, clientSecret } = this.ssoConfig

        try {
            const logoutEndpoint = issuer + '/protocol/openid-connect/logout'
            
            // Notify Keycloak about the logout
            const response = await axios.post(
                logoutEndpoint,
                {
                    client_id: clientID,
                    client_secret: clientSecret,
                    refresh_token: ssoAccessToken
                },
                {
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    timeout: 5000
                }
            )
            
            return { message: 'Logout successful' }
        } catch (error) {
            // Logout errors are usually not critical - user is already logged out locally
            console.warn('Keycloak logout notification failed:', error)
            return { message: 'Local logout successful, remote logout failed' }
        }
    }

    private async handleKeycloakCallback(
        req: Request,
        issuer: string,
        profile: Profile,
        context: object,
        idToken: string | object,
        accessToken: string | object,
        refreshToken: string,
        done: VerifyCallback
    ) {
        if ( profile.emails && profile.emails.length > 0 ) {
            const email = profile.emails[ 0 ].value
            return this.verifyAndLogin( this.app, email, done, profile, accessToken, refreshToken )
        } else {
            await auditService.recordLoginActivity(
                '<empty>',
                LoginActivityCode.UNKNOWN_USER,
                ErrorMessage.UNKNOWN_USER,
                this.getProviderName()
            )
            return done( { name: 'SSO_LOGIN_FAILED', message: ErrorMessage.UNKNOWN_USER }, undefined )
        }
    }
}

export default KeycloakSSO
