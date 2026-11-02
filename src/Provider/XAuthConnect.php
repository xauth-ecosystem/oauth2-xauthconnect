<?php

namespace ChernegaSergiy\XAuthConnect\OAuth2\Client\Provider;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;

/**
 * Represents an XAuthConnect provider for the league/oauth2-client.
 * This provider implements the OpenID Connect flow, including discovery and ID token validation.
 */
class XAuthConnect extends AbstractProvider
{
    use BearerAuthorizationTrait;

    public ?string $baseAuthorizationUrl = null;

    public ?string $baseAccessTokenUrl = null;

    public ?string $resourceOwnerDetailsUrl = null;

    public ?string $introspectUrl = null;

    public ?string $revokeUrl = null;

    public ?string $jwksUrl = null;

    protected array $options = [];

    /**
     * Initializes the provider with options.
     *
     * @param  array                     $options       Provider options, including 'issuer', 'clientId', 'clientSecret', and 'redirectUri'.
     * @param  array                     $collaborators An array of collaborators that may be used to override this provider's default behavior.
     * @throws \InvalidArgumentException If required options are missing.
     */
    public function __construct(array $options = [], array $collaborators = [])
    {
        parent::__construct($options, $collaborators);
        $this->options = array_merge($this->options, $options);

        if (! empty($this->options['issuer'])) {
            $this->discoverEndpoints($this->options['issuer']);
        }

        $urlOptions = [
            'baseAuthorizationUrl',
            'baseAccessTokenUrl',
            'resourceOwnerDetailsUrl',
            'introspectUrl',
            'revokeUrl',
            'jwksUrl',
        ];

        foreach ($urlOptions as $option) {
            if (! empty($this->options[$option])) {
                $this->{$option} = $this->options[$option];
            }
        }

        foreach ($urlOptions as $option) {
            if (empty($this->{$option})) {
                throw new \InvalidArgumentException("The '{$option}' option is required or must be discoverable from the 'issuer' URL.");
            }
        }
    }

    /**
     * Populates OIDC endpoint properties by discovering them from the issuer's .well-known configuration.
     *
     * @param  string            $issuer The issuer URL.
     * @return void
     * @throws \RuntimeException If discovery fails or the document is invalid.
     */
    protected function discoverEndpoints(string $issuer) : void
    {
        $wellKnownUrl = rtrim($issuer, '/') . '/.well-known/openid-configuration';

        try {
            $httpClient = $this->getHttpClient();
            $response = $httpClient->get($wellKnownUrl);
            $data = json_decode((string) $response->getBody(), true);

            if (JSON_ERROR_NONE !== json_last_error()) {
                throw new \RuntimeException('Failed to parse discovery document: ' . json_last_error_msg());
            }

            $this->baseAuthorizationUrl = $data['authorization_endpoint'] ?? null;
            $this->baseAccessTokenUrl = $data['token_endpoint'] ?? null;
            $this->resourceOwnerDetailsUrl = $data['userinfo_endpoint'] ?? null;
            $this->introspectUrl = $data['introspection_endpoint'] ?? null;
            $this->revokeUrl = $data['revocation_endpoint'] ?? null;
            $this->jwksUrl = $data['jwks_uri'] ?? null;

        } catch (\Exception $e) {
            throw new \RuntimeException('Failed to discover endpoints: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Requests an access token and automatically validates the ID token if received.
     *
     * @param  mixed                     $grant   The grant type to use.
     * @param  array                     $options Additional options for the grant.
     * @return AccessTokenInterface      The access token, including validated ID token claims.
     * @throws IdentityProviderException If the ID token validation fails.
     */
    public function getAccessToken($grant, array $options = []) : AccessTokenInterface
    {
        $accessToken = parent::getAccessToken($grant, $options);

        $idToken = $accessToken->getValues()['id_token'] ?? null;

        if ($idToken) {
            $nonce = $_SESSION['oauth2nonce'] ?? null;
            unset($_SESSION['oauth2nonce']);

            $validatedClaims = $this->getValidatedClaims($idToken, $nonce);
            $values = array_merge($accessToken->getValues(), ['id_token_claims' => $validatedClaims]);
            $accessToken = new AccessToken(array_merge($accessToken->jsonSerialize(), $values));
        }

        return $accessToken;
    }

    /**
     * Performs cryptographic validation of the ID token's signature and claims.
     *
     * @param  string                    $idToken       The ID token string.
     * @param  string|null               $expectedNonce The nonce sent in the authorization request to mitigate replay attacks.
     * @return array                     The decoded and validated claims as an array.
     * @throws IdentityProviderException If any part of the validation fails.
     */
    private function getValidatedClaims(string $idToken, ?string $expectedNonce) : array
    {
        $jwks = $this->fetchJwks();
        $keys = JWK::parseKeySet($jwks);

        $decoded = JWT::decode($idToken, $keys);

        if ($decoded->iss !== $this->getConfiguredIssuer()) {
            throw new IdentityProviderException('Invalid issuer claim', 0, $idToken);
        }

        $aud = is_array($decoded->aud) ? $decoded->aud : [$decoded->aud];
        if (! in_array($this->options['clientId'], $aud, true)) {
            throw new IdentityProviderException('Invalid audience claim', 0, $idToken);
        }

        if (null !== $expectedNonce) {
            if (empty($decoded->nonce)) {
                throw new IdentityProviderException('ID token is missing nonce claim', 0, $idToken);
            }
            if ($decoded->nonce !== $expectedNonce) {
                throw new IdentityProviderException('Invalid nonce', 0, $idToken);
            }
        }

        return (array) $decoded;
    }

    /**
     * Fetches the JSON Web Key Set (JWKS) from the provider's jwks_uri.
     *
     * @return array The full JWKS structure as an array.
     */
    private function fetchJwks() : array
    {
        $response = $this->getHttpClient()->get($this->jwksUrl);
        $data = json_decode((string) $response->getBody(), true);
        return $data;
    }

    /**
     * Gets the configured issuer URL from the provider options.
     *
     * @return string The issuer URL.
     */
    private function getConfiguredIssuer() : string
    {
        return $this->options['issuer'];
    }

    /**
     * Gets the base URL for provider authorization.
     *
     * @return string The authorization URL.
     */
    public function getBaseAuthorizationUrl() : string
    {
        return $this->baseAuthorizationUrl;
    }

    /**
     * Gets the base URL for requesting an access token.
     *
     * @param  array  $params Query parameters for the token URL.
     * @return string The access token URL.
     */
    public function getBaseAccessTokenUrl(array $params) : string
    {
        return $this->baseAccessTokenUrl;
    }

    /**
     * Gets the URL for requesting the resource owner's details.
     *
     * @param  AccessToken $token The access token to use for the request.
     * @return string      The resource owner details URL.
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token) : string
    {
        return $this->resourceOwnerDetailsUrl;
    }

    /**
     * Gets the PKCE (Proof Key for Code Exchange) method used by the provider.
     *
     * @return string The PKCE method name.
     */
    protected function getPkceMethod() : string
    {
        return 'S256';
    }

    /**
     * Sends a request to the introspection endpoint to validate a token.
     *
     * @param  string $token The token to introspect.
     * @return array  The introspection result as an array.
     */
    public function introspectToken(string $token) : array
    {
        $params = [
            'token' => $token,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
        ];

        $request = $this->createRequest(self::METHOD_POST, $this->introspectUrl, null, [
            'body' => $this->buildQueryString($params)
        ]);

        return $this->getParsedResponse($request);
    }

    /**
     * Sends a request to the revocation endpoint to invalidate a token.
     *
     * @param  string $token The token to revoke.
     * @return void
     */
    public function revokeToken(string $token) : void
    {
        $params = [
            'token' => $token,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
        ];

        $request = $this->createRequest(self::METHOD_POST, $this->revokeUrl, null, [
            'body' => $this->buildQueryString($params)
        ]);

        $this->getParsedResponse($request);
    }

    /**
     * Gets the default scopes used by this provider.
     *
     * @return array A list of default scopes.
     */
    protected function getDefaultScopes() : array
    {
        return ['openid', 'profile:nickname', 'profile:uuid'];
    }

    /**
     * Gets the string used to separate scopes.
     *
     * @return string The scope separator.
     */
    protected function getScopeSeparator() : string
    {
        return ' ';
    }

    /**
     * Checks the provider response for errors.
     *
     * @param  ResponseInterface         $response The provider's response.
     * @param  array|string              $data     The decoded response data.
     * @return void
     * @throws IdentityProviderException If the response contains an error.
     */
    protected function checkResponse(ResponseInterface $response, $data) : void
    {
        if (! empty($data['error'])) {
            $code = $response->getStatusCode();
            $error = $data['error_description'] ?? $data['error'];
            throw new IdentityProviderException($error, $code, $data);
        }
    }

    /**
     * Creates a resource owner object from a successful user details request.
     *
     * @param  array            $response The response from the resource owner details endpoint.
     * @param  AccessToken      $token    The access token used for the request.
     * @return XAuthConnectUser The created resource owner.
     */
    protected function createResourceOwner(array $response, AccessToken $token) : XAuthConnectUser
    {
        return new XAuthConnectUser($response);
    }
}
