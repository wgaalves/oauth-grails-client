package br.com.muvedigital.client

import groovy.time.TimeCategory

class OauthTokenTagLib {

    static namespace = "oauth"
    static defaultEncodeAs = [taglib: 'none']

    def renderToken = { attrs ->

        def tokenDetails = session.accessToken
        def acessroles = ''
        def roles = session.roles

        out << '<div class"mvpOauth2">'
        out << "<h2>Oauth Token Value</h2>"
        out << tokenDetails.access_token

        out << "<h2>Expiration Time</h2>"

        use (TimeCategory) {
            Integer expirySeconds = tokenDetails.expires_in as Integer
            out << expirySeconds.seconds.from.now
        }

        out << "<h2>Refesh Token</h2>"
        out << tokenDetails.refresh_token

        out << "<h2>Scope</h2>"
        out << tokenDetails.scope

        out << "<h2>Token Type</h2>"
        out << tokenDetails.token_type

        if(roles) {
            roles.role.each {
                acessroles = acessroles + it.authority + ', '
            }
            out << "<h2>Additional Info: username</h2>"
            out << roles.user

            out << "<h2>Additional Info: Roles</h2>"
            out << acessroles
        }



        out << '</div>'


    }
}
