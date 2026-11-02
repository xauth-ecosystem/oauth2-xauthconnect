<?php

namespace ChernegaSergiy\XAuthConnect\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

/**
 * Represents a resource owner, containing user data returned from the provider.
 */
class XAuthConnectUser implements ResourceOwnerInterface
{
    /**
     * @var array Raw response data.
     */
    protected array $response;

    /**
     * Creates a new resource owner.
     *
     * @param array $response The raw response data from the provider.
     */
    public function __construct(array $response)
    {
        $this->response = $response;
    }

    /**
     * Gets the resource owner's identifier.
     *
     * @return string|null The identifier (subject) or null if not available.
     */
    public function getId() : ?string
    {
        return $this->response['sub'] ?? $this->response['profile:uuid'] ?? null;
    }

    /**
     * Gets the resource owner's nickname.
     *
     * @return string|null The nickname or null if not available.
     */
    public function getNickname() : ?string
    {
        return $this->response['nickname'] ?? $this->response['profile:nickname'] ?? null;
    }

    /**
     * Gets all resource owner details as an array.
     *
     * @return array The raw response data.
     */
    public function toArray() : array
    {
        return $this->response;
    }
}
