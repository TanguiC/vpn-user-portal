<?php

/*
 * eduVPN - End-user friendly VPN.
 *
 * Copyright: 2016-2018, The Commons Conservancy eduVPN Programme
 * SPDX-License-Identifier: AGPL-3.0+
 */

namespace SURFnet\VPN\Portal;

use fkooman\OAuth\Server\ClientInfo;

class OAuthClientInfo
{
    /**
     * @param string $clientId
     *
     * @return false|\fkooman\OAuth\Server\ClientInfo
     */
    public static function getClient($clientId)
    {
        $clientInfo = [
            // org.eduvpn.app is DEPRECATED and will be removed once all
            // clients use their new client_id, but we'd have to wait for a
            // new release of those apps
            'org.eduvpn.app' => [
                'redirect_uri_list' => [
                    'org.eduvpn.app:/api/callback',
                    'http://127.0.0.1:{PORT}/callback',
                    'http://[::1]:{PORT}/callback',
                ],
                'display_name' => 'eduVPN (legacy)',
                'require_approval' => true,
            ],
            // Windows
            'org.eduvpn.app.windows' => [
                'redirect_uri_list' => [
                    'http://127.0.0.1:{PORT}/callback',
                    'http://[::1]:{PORT}/callback',
                ],
                'display_name' => 'eduVPN for Windows',
                'require_approval' => true,
            ],
            // Windows (LC)
            'org.letsconnect-vpn.app.windows' => [
                'redirect_uri_list' => [
                    'http://127.0.0.1:{PORT}/callback',
                    'http://[::1]:{PORT}/callback',
                ],
                'display_name' => 'Let\'s Connect! for Windows',
                'require_approval' => true,
            ],
            // Android
            'org.eduvpn.app.android' => [
                'redirect_uri_list' => [
                    'org.eduvpn.app:/api/callback',
                    'https://android.app.eduvpn.org/api/callback',  // Android >= 6
                ],
                'display_name' => 'eduVPN for Android',
                'require_approval' => true,
            ],
            // Android (LC)
            'org.letsconnect-vpn.app.android' => [
                'redirect_uri_list' => [
                    'org.letsconnect-vpn.app:/api/callback',
                    'https://android.app.letsconnect-vpn.org/api/callback',  // Android >= 6
                ],
                'display_name' => 'Let\'s Connect! for Android',
                'require_approval' => true,
            ],
            // iOS
            'org.eduvpn.app.ios' => [
                'redirect_uri_list' => [
                    'https://ios.app.eduvpn.org/auth/app/redirect/',
                    'https://ios.app.eduvpn.org/auth/app/redirect/development/',
                ],
                'display_name' => 'eduVPN for iOS',
                'require_approval' => false,
            ],
            // iOS (LC)
            'org.letsconnect-vpn.app.ios' => [
                'redirect_uri_list' => [
                    'https://ios.app.letsconnect-vpn.org/auth/app/redirect/',
                    'https://ios.app.letsconnect-vpn.org/auth/app/redirect/development/',
                ],
                'display_name' => 'Let\'s Connect! for iOS',
                'require_approval' => false,
            ],
            // macOS
            'org.eduvpn.app.macos' => [
                'redirect_uri_list' => [
                    'org.eduvpn.app:/api/callback',
                    'http://127.0.0.1:{PORT}/callback',
                    'http://[::1]:{PORT}/callback',
                ],
                'display_name' => 'eduVPN for macOS',
                'require_approval' => true,
            ],
            // macOS (LC)
            'org.letsconnect-vpn.app.macos' => [
                'redirect_uri_list' => [
                    'org.letsconnect-vpn.app:/api/callback',
                    'http://127.0.0.1:{PORT}/callback',
                    'http://[::1]:{PORT}/callback',
                ],
                'display_name' => 'Let\'s Connect! for macOS',
                'require_approval' => true,
            ],
            // Linux
            'org.eduvpn.app.linux' => [
                'redirect_uri_list' => [
                    'org.eduvpn.app:/api/callback',
                    'http://127.0.0.1:{PORT}/callback',
                    'http://[::1]:{PORT}/callback',
                ],
                'display_name' => 'eduVPN for Linux',
                'require_approval' => true,
            ],
            // Linux (LC)
            'org.letsconnect-vpn.app.linux' => [
                'redirect_uri_list' => [
                    'org.letsconnect-vpn.app:/api/callback',
                    'http://127.0.0.1:{PORT}/callback',
                    'http://[::1]:{PORT}/callback',
                ],
                'display_name' => 'Let\'s Connect! for Linux',
                'require_approval' => true,
            ],
        ];

        if (!array_key_exists($clientId, $clientInfo)) {
            return false;
        }

        return new ClientInfo($clientInfo[$clientId]);
    }
}
