package br.com.muvedigital.client

import com.google.gson.JsonObject
import groovy.json.JsonSlurper
import org.apache.http.HttpResponse
import org.apache.http.NameValuePair
import org.apache.http.client.HttpClient
import org.apache.http.client.entity.UrlEncodedFormEntity
import org.apache.http.client.methods.HttpPost
import org.apache.http.impl.client.DefaultHttpClient
import org.apache.http.message.BasicNameValuePair
import org.apache.http.util.EntityUtils
import org.codehaus.groovy.grails.commons.GrailsApplication
import org.codehaus.groovy.grails.web.mapping.LinkGenerator

import javax.annotation.PreDestroy

class OauthService {

    LinkGenerator grailsLinkGenerator
    GrailsApplication grailsApplication

    @Lazy
    private String oauthProviderUrl = grailsApplication.config.oauthProvider.baseUrl + '/oauth/token'

    private HttpClient httpClient = new DefaultHttpClient()

    /**
     * Exchange an authorization code for an access token
     * @param authCode
     * @return
     */
    def exchangeAuthCode(String authCode) {

        def callback = grailsLinkGenerator.link(controller: 'auth', action: 'callback', absolute: true)

        def params = [
                // the scope param is not required by the OAuth spec. it's a workaround for this issue
                // https://github.com/bluesliverx/grails-spring-security-oauth2-provider/issues/64
                scope        : 'read',
                grant_type   : 'authorization_code',
                code         : authCode,
                client_id    : 'my-client',
                client_secret: 'secret-client',
                redirect_uri : callback
        ]

        getJsonResponse(params)
    }

    def refreshToken(String refreshToken) {
        def params = [
                grant_type   : 'refresh_token',
                refresh_token: refreshToken,
                client_id    : 'my-client',
                client_secret: 'secret-client',
                scope        : 'read'
        ]

        getJsonResponse(params)
    }

    private getJsonResponse(Map<String, String> params) {
        HttpPost httpPost = new HttpPost(oauthProviderUrl)
        log.debug(oauthProviderUrl)
        List<NameValuePair> postParams = params.collect {
            new BasicNameValuePair(it.key, it.value)
        }

        httpPost.entity = new UrlEncodedFormEntity(postParams)
        HttpResponse response = httpClient.execute(httpPost)

        try {
            String responseBody = response.entity.content.text
            log.debug("OAuth response: $responseBody")


            def slurper = new groovy.json.JsonSlurper()
            def result = slurper.parseText(responseBody)
            log.debug("Resultado " + result.access_token)

            EntityUtils.consume(response.entity)

            new JsonSlurper().parseText(responseBody)

        } finally {
            httpPost.releaseConnection()
        }
    }
    def getRole(String accesskey){

        def roleUrl = grailsApplication.config.oauthProvider.baseUrl + '/securedOAuth2Resources/clientRole'


        def params = [accesstoken : accesskey]

        HttpPost httpPost = new HttpPost(roleUrl)
        List<NameValuePair> postParams = params.collect {
            new BasicNameValuePair(it.key, it.value)
        }

        httpPost.addHeader('authorization','Bearer '+ accesskey.toString())
        httpPost.addHeader('Content-Type', 'application/x-www-form-urlencoded' )
        httpPost.addHeader('Cache-Control', 'no-cache')


        httpPost.entity = new UrlEncodedFormEntity(postParams)
        HttpResponse response = httpClient.execute(httpPost)

        try {
            String responseBody = response.entity.content.text
            log.debug "OAuth response access: $responseBody"


            EntityUtils.consume(response.entity)
            new JsonSlurper().parseText(responseBody)

        } catch (Exception e){
            log.debug(e.getMessage())
        }finally {
            httpPost.releaseConnection()
        }

    }

    @PreDestroy
    private void close() {
        httpClient.connectionManager.shutdown()
    }
}