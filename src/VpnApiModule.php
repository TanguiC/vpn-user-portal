<?php

/*
 * eduVPN - End-user friendly VPN.
 *
 * Copyright: 2016-2018, The Commons Conservancy eduVPN Programme
 * SPDX-License-Identifier: AGPL-3.0+
 */

namespace SURFnet\VPN\Portal;

use DateTime;
use DateTimeZone;
use SURFnet\VPN\Common\Http\ApiErrorResponse;
use SURFnet\VPN\Common\Http\ApiResponse;
use SURFnet\VPN\Common\Http\Exception\InputValidationException;
use SURFnet\VPN\Common\Http\InputValidation;
use SURFnet\VPN\Common\Http\Request;
use SURFnet\VPN\Common\Http\Response;
use SURFnet\VPN\Common\Http\Service;
use SURFnet\VPN\Common\Http\ServiceModuleInterface;
use SURFnet\VPN\Common\HttpClient\ServerClient;
use SURFnet\VPN\Common\ProfileConfig;

class VpnApiModule implements ServiceModuleInterface
{
    /** @var \SURFnet\VPN\Common\HttpClient\ServerClient */
    private $serverClient;

    /** @var bool */
    private $shuffleHosts;

    public function __construct(ServerClient $serverClient)
    {
        $this->serverClient = $serverClient;
        $this->shuffleHosts = true;
    }

    /**
     * @param bool $shuffleHosts
     *
     * @return void
     */
    public function setShuffleHosts($shuffleHosts)
    {
        $this->shuffleHosts = (bool) $shuffleHosts;
    }

    /**
     * @return void
     */
    public function init(Service $service)
    {
        // API 1, 2
        $service->get(
            '/profile_list',
            /**
             * @return ApiResponse
             */
            function (Request $request, array $hookData) {
                $userInfo = $hookData['auth'];

                $profileList = $this->serverClient->get('profile_list');
                $userGroups = $this->serverClient->get('user_groups', ['user_id' => $userInfo->id()]);

                $userProfileList = [];
                foreach ($profileList as $profileId => $profileData) {
                    $profileConfig = new ProfileConfig($profileData);
                    if ($profileConfig->getItem('enableAcl')) {
                        // is the user member of the aclGroupList?
                        if (!self::isMember($userGroups, $profileConfig->getSection('aclGroupList')->toArray())) {
                            continue;
                        }
                    }

                    $userProfileList[] = [
                        'profile_id' => $profileId,
                        'display_name' => $profileConfig->getItem('displayName'),
                        'two_factor' => $profileConfig->getItem('twoFactor'),
                    ];
                }

                return new ApiResponse('profile_list', $userProfileList);
            }
        );

        // API 2
        $service->get(
            '/user_info',
            /**
             * @return ApiResponse
             */
            function (Request $request, array $hookData) {
                $userInfo = $hookData['auth'];

                $hasYubiKeyId = $this->serverClient->get('has_yubi_key_id', ['user_id' => $userInfo->id()]);
                $hasTotpSecret = $this->serverClient->get('has_totp_secret', ['user_id' => $userInfo->id()]);
                $isDisabledUser = $this->serverClient->get('is_disabled_user', ['user_id' => $userInfo->id()]);

                $twoFactorTypes = [];
                if ($hasYubiKeyId) {
                    $twoFactorTypes[] = 'yubi';
                }
                if ($hasTotpSecret) {
                    $twoFactorTypes[] = 'totp';
                }

                return new ApiResponse(
                    'user_info',
                    [
                        'user_id' => $userInfo->id(),
                        'two_factor_enrolled' => $hasYubiKeyId || $hasTotpSecret,
                        'two_factor_enrolled_with' => $twoFactorTypes,
                        'is_disabled' => $isDisabledUser,
                    ]
                );
            }
        );

        // API 2
        $service->post(
            '/create_keypair',
            /**
             * @return ApiResponse
             */
            function (Request $request, array $hookData) {
                $userInfo = $hookData['auth'];

                try {
                    $displayName = InputValidation::displayName($request->getPostParameter('display_name'));
                    $clientCertificate = $this->getCertificate($userInfo->id(), $displayName);

                    return new ApiResponse(
                        'create_keypair',
                        [
                            'certificate' => $clientCertificate['certificate'],
                            'private_key' => $clientCertificate['private_key'],
                        ]
                    );
                } catch (InputValidationException $e) {
                    return new ApiErrorResponse('create_keypair', $e->getMessage());
                }
            }
        );

        $service->post(
            '/add_client_certificate_fingerprint',
            /**
             * @return ApiResponse
             */
            function (Request $request, array $hookData) {
                $userInfo = $hookData['auth'];

                try {
                    $displayName = InputValidation::displayName($request->getPostParameter('display_name'));
                    $certFingerprint = InputValidation::certFingerprint($request->getPostParameter('fingerprint'));

                    $this->serverClient->post(
                        'add_client_certificate_fingerprint',
                        [
                            'user_id' => $userInfo->id(),
                            'display_name' => $displayName,
                            'fingerprint' => $certFingerprint,
                        ]
                    );

                    return new ApiResponse(
                        'add_client_certificate_fingerprint'
                    );
                } catch (InputValidationException $e) {
                    return new ApiErrorResponse('create_keypair', $e->getMessage());
                }
            }
        );

        // API 2
        $service->get(
            '/check_certificate',
            /**
             * @return \SURFnet\VPN\Common\Http\Response
             */
            function (Request $request, array $hookData) {
                $userInfo = $hookData['auth'];

                $commonName = InputValidation::commonName($request->getQueryParameter('common_name'));
                $clientCertificateInfo = $this->serverClient->get('client_certificate_info', ['common_name' => $commonName]);
                if (false === $clientCertificateInfo) {
                    $isValid = false;
                } else {
                    $isValid = (bool) !$clientCertificateInfo['certificate_is_disabled'] && !$clientCertificateInfo['user_is_disabled'];
                }

                return new ApiResponse(
                    'check_certificate',
                    [
                        'data' => [
                            'is_valid' => $isValid,
                        ],
                    ]
                );
            }
        );

        // API 2
        $service->get(
            '/profile_config',
            /**
             * @return \SURFnet\VPN\Common\Http\Response
             */
            function (Request $request, array $hookData) {
                $userInfo = $hookData['auth'];

                try {
                    $requestedProfileId = InputValidation::profileId($request->getQueryParameter('profile_id'));

                    $profileList = $this->serverClient->get('profile_list');
                    $userGroups = $this->serverClient->get('user_groups', ['user_id' => $userInfo->id()]);

                    $availableProfiles = [];
                    foreach ($profileList as $profileId => $profileData) {
                        $profileConfig = new ProfileConfig($profileData);
                        if ($profileConfig->getItem('enableAcl')) {
                            // is the user member of the aclGroupList?
                            if (!self::isMember($userGroups, $profileConfig->getSection('aclGroupList')->toArray())) {
                                continue;
                            }
                        }

                        $availableProfiles[] = $profileId;
                    }

                    if (!in_array($requestedProfileId, $availableProfiles, true)) {
                        return new ApiErrorResponse('profile_config', 'user has no access to this profile');
                    }

                    return $this->getConfigOnly($requestedProfileId);
                } catch (InputValidationException $e) {
                    return new ApiErrorResponse('profile_config', $e->getMessage());
                }
            }
        );

        // API 1
        $service->post(
            '/create_config',
            /**
             * @return \SURFnet\VPN\Common\Http\Response
             */
            function (Request $request, array $hookData) {
                $userInfo = $hookData['auth'];

                try {
                    $displayName = InputValidation::displayName($request->getPostParameter('display_name'));
                    $profileId = InputValidation::profileId($request->getPostParameter('profile_id'));

                    return $this->getConfig($request->getServerName(), $profileId, $userInfo->id(), $displayName);
                } catch (InputValidationException $e) {
                    return new ApiErrorResponse('create_config', $e->getMessage());
                }
            }
        );

        $service->post(
            '/two_factor_enroll_yubi',
            /**
             * @return \SURFnet\VPN\Common\Http\Response
             */
            function (Request $request, array $hookData) {
                $userInfo = $hookData['auth'];

                try {
                    $hasYubiKeyId = $this->serverClient->get('has_yubi_key_id', ['user_id' => $userInfo->id()]);
                    $hasTotpSecret = $this->serverClient->get('has_totp_secret', ['user_id' => $userInfo->id()]);
                    if ($hasYubiKeyId || $hasTotpSecret) {
                        return new ApiErrorResponse('two_factor_enroll_yubi', 'user already enrolled');
                    }
                    $yubiKeyOtp = InputValidation::yubiKeyOtp($request->getPostParameter('yubi_key_otp'));
                    $this->serverClient->post('set_yubi_key_id', ['user_id' => $userInfo->id(), 'yubi_key_otp' => $yubiKeyOtp]);

                    return new ApiResponse('two_factor_enroll_yubi');
                } catch (InputValidationException $e) {
                    return new ApiErrorResponse('two_factor_enroll_yubi', $e->getMessage());
                }
            }
        );

        $service->post(
            '/two_factor_enroll_totp',
            /**
             * @return \SURFnet\VPN\Common\Http\Response
             */
            function (Request $request, array $hookData) {
                $userInfo = $hookData['auth'];

                $hasYubiKeyId = $this->serverClient->get('has_yubi_key_id', ['user_id' => $userInfo->id()]);
                $hasTotpSecret = $this->serverClient->get('has_totp_secret', ['user_id' => $userInfo->id()]);
                if ($hasYubiKeyId || $hasTotpSecret) {
                    return new ApiErrorResponse('two_factor_enroll_totp', 'user already enrolled');
                }

                try {
                    $totpKey = InputValidation::totpKey($request->getPostParameter('totp_key'));
                    $totpSecret = InputValidation::totpSecret($request->getPostParameter('totp_secret'));
                } catch (InputValidationException $e) {
                    return new ApiErrorResponse('two_factor_enroll_totp', $e->getMessage());
                }
                $this->serverClient->post('set_totp_secret', ['user_id' => $userInfo->id(), 'totp_secret' => $totpSecret, 'totp_key' => $totpKey]);

                return new ApiResponse('two_factor_enroll_totp');
            }
        );

        // API 1, 2
        $service->get(
            '/user_messages',
            /**
             * @return ApiResponse
             */
            function (Request $request, array $hookData) {
                $userInfo = $hookData['auth'];

                $msgList = [];

                return new ApiResponse(
                    'user_messages',
                    $msgList
                );
            }
        );

        // API 1, 2
        $service->get(
            '/system_messages',
            /**
             * @return ApiResponse
             */
            function (Request $request, array $hookData) {
                $msgList = [];

                $motdMessages = $this->serverClient->get('system_messages', ['message_type' => 'motd']);
                foreach ($motdMessages as $motdMessage) {
                    $dateTime = new DateTime($motdMessage['date_time']);
                    $dateTime->setTimezone(new DateTimeZone('UTC'));

                    $msgList[] = [
                        // no support yet for 'motd' type in application API
                        'type' => 'notification',
                        'date_time' => $dateTime->format('Y-m-d\TH:i:s\Z'),
                        'message' => $motdMessage['message'],
                    ];
                }

                return new ApiResponse(
                    'system_messages',
                    $msgList
                );
            }
        );
    }

    /**
     * @param string $serverName
     * @param string $profileId
     * @param string $userId
     * @param string $displayName
     *
     * @return Response
     */
    private function getConfig($serverName, $profileId, $userId, $displayName)
    {
        // obtain information about this profile to be able to construct
        // a client configuration file
        $profileList = $this->serverClient->get('profile_list');
        $profileData = $profileList[$profileId];

        // create a certificate
        $clientCertificate = $this->getCertificate($userId, $displayName);
        // get the CA & tls-auth
        $serverInfo = $this->serverClient->get('server_info', ['profile_id' => $profileId]);

        $clientConfig = ClientConfig::get($profileData, $serverInfo, $clientCertificate, $this->shuffleHosts);
        $clientConfig = str_replace("\n", "\r\n", $clientConfig);

        $response = new Response(200, 'application/x-openvpn-profile');
        $response->setBody($clientConfig);

        return $response;
    }

    /**
     * @param string $profileId
     *
     * @return Response
     */
    private function getConfigOnly($profileId)
    {
        // obtain information about this profile to be able to construct
        // a client configuration file
        $profileList = $this->serverClient->get('profile_list');
        $profileData = $profileList[$profileId];

        // get the CA & tls-auth
        $serverInfo = $this->serverClient->get('server_info', ['profile_id' => $profileId]);

        $clientConfig = ClientConfig::get($profileData, $serverInfo, [], $this->shuffleHosts);
        $clientConfig = str_replace("\n", "\r\n", $clientConfig);

        $response = new Response(200, 'application/x-openvpn-profile');
        $response->setBody($clientConfig);

        return $response;
    }

    /**
     * @param string $userId
     * @param string $displayName
     *
     * @return array|bool
     */
    private function getCertificate($userId, $displayName)
    {
        // create a certificate
        return $this->serverClient->post(
            'add_client_certificate',
            [
                'user_id' => $userId,
                'display_name' => $displayName,
            ]
        );
    }

    /**
     * @return bool
     */
    private static function isMember(array $userGroups, array $aclGroupList)
    {
        // if any of the groups in userGroups is part of aclGroupList return
        // true, otherwise false
        foreach ($userGroups as $userGroup) {
            if (in_array($userGroup['id'], $aclGroupList, true)) {
                return true;
            }
        }

        return false;
    }
}
