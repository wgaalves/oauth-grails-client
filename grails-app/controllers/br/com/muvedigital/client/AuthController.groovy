package br.com.muvedigital.client

class AuthController {

    OauthService oauthService

    static allowedMethods = [callback: 'GET', clearToken: 'GET']

    /**
     * The callback action for OAuth2 login
     */
    def callback(String code) {
        def response = oauthService.exchangeAuthCode(code)

        if (response.error) {
            log.error "Auth code exchange failed: $response"
        } else {
            session.accessToken = response
            //getRole(response.access_token)
            oauthService.getRole(response.access_token)

            log.info "Exchanged auth code $code for access token $response"
        }
        log.debug(response.access_token)
        redirect uri: '/'
    }

    def clearToken() {
        session.removeAttribute('accessToken')
        redirect uri: '/'
    }

    def refreshToken() {
        log.debug(params)

        if (session.accessToken) {
             def response = oauthService.refreshToken(session.accessToken.refresh_token)

            if (response.error) {
                log.error "Access token refresh failed: $response"

            } else {
                session.accessToken = response
                log.info "Refreshed access token $response"
            }
        }

        redirect uri: '/'
    }


    def getRoles(){
        if (session.accessToken) {
            def response = oauthService.getRole(session.accessToken.access_token)

            if (response.error) {
                log.error "get Roles failed: $response"

            } else {
                session.roles = response
                log.info "Roles  $response"
            }
        }
        redirect uri: '/'
    }
}
