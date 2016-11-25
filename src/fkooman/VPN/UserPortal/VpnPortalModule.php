<?php
/**
 * Copyright 2016 François Kooman <fkooman@tuxed.net>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
namespace fkooman\VPN\UserPortal;

use fkooman\Http\Exception\BadRequestException;
use fkooman\Http\RedirectResponse;
use fkooman\Http\Request;
use fkooman\Http\Response;
use fkooman\Rest\Plugin\Authentication\UserInfoInterface;
use fkooman\Rest\Service;
use fkooman\Rest\ServiceModuleInterface;
use fkooman\Tpl\TemplateManagerInterface;
use BaconQrCode\Renderer\Image\Png;
use BaconQrCode\Writer;
use Otp\GoogleAuthenticator;
use Otp\Otp;
use Base32\Base32;
use fkooman\Http\Session;

class VpnPortalModule implements ServiceModuleInterface
{
    /** @var \fkooman\Tpl\TemplateManagerInterface */
    private $templateManager;

    /** @var VpnServerApiClient */
    private $vpnServerApiClient;

    /** @var UserTokens */
    private $userTokens;

    /** @var \fkooman\Http\Session */
    private $session;

    public function __construct(TemplateManagerInterface $templateManager, VpnServerApiClient $vpnServerApiClient, UserTokens $userTokens, Session $session)
    {
        $this->templateManager = $templateManager;
        $this->vpnServerApiClient = $vpnServerApiClient;
        $this->userTokens = $userTokens;
        $this->session = $session;
    }

    public function init(Service $service)
    {
        $noAuth = array(
            'fkooman\Rest\Plugin\Authentication\AuthenticationPlugin' => array(
                'enabled' => false,
            ),
        );

        $userAuth = array(
            'fkooman\Rest\Plugin\Authentication\AuthenticationPlugin' => array(
                'activate' => array('user'),
            ),
        );

        /* REDIRECTS **/
        $service->get(
            '/config/',
            function (Request $request) {
                return new RedirectResponse($request->getUrl()->getRootUrl(), 301);
            },
            $noAuth
        );

        $service->get(
            '/',
            function (Request $request) {
                return new RedirectResponse($request->getUrl()->getRootUrl().'zerotier', 302);
            },
            $noAuth
        );

        /* PAGES */
        $service->get(
            '/account',
            function (Request $request, UserInfoInterface $u) {
                $otpSecret = $this->vpnServerApiClient->getOtpSecret($u->getUserId());
                $userGroups = $this->vpnServerApiClient->getUserGroups($u->getUserId());
                $serverPools = $this->vpnServerApiClient->getServerPools();

                $groupMembership = [];
                foreach ($serverPools as $pool) {
                    if (in_array($pool['id'], $userGroups)) {
                        $groupMembership[] = $pool['name'];
                    }
                }

                return $this->templateManager->render(
                    'vpnPortalAccount',
                    array(
                        'otpEnabled' => $otpSecret,
                        'userId' => $u->getUserId(),
                        'userTokens' => $this->userTokens->getUserAccessTokens($u->getUserId()),
                        'userGroups' => $userGroups,
                        'zeroTierClients' => $this->vpnServerApiClient->getZeroTierClients($u->getUserId()),
                    )
                );
            },
            $userAuth
        );

        $service->get(
            '/attributes',
            function (Request $request, UserInfoInterface $u) {
                $output = '';
                foreach ($_SERVER as $key => $value) {
                    if (substr($key, 0, 7) == 'MELLON_') {
                        $output .= $key.' = '.$value.'<br>';
                    }
                }

                return $output;
            },
            $userAuth
        );

        $service->get(
            '/zerotier',
            function (Request $request, UserInfoInterface $u) {
                $networks = $this->vpnServerApiClient->getZeroTierNetworks($u->getUserId());
                $guestNetworks = $this->vpnServerApiClient->getZeroTierGuestNetworks($u->getUserId());
                $userGroups = $this->vpnServerApiClient->getUserGroups($u->getUserId());

                // add group_id to group_name
                for ($i = 0; $i < count($networks); ++$i) {
                    $networks[$i]['group_name'] = self::idToName($userGroups, $networks[$i]['group_id']);
                }

                // add group_id to group_name
                for ($i = 0; $i < count($guestNetworks); ++$i) {
                    $guestNetworks[$i]['group_name'] = self::idToName($userGroups, $guestNetworks[$i]['group_id']);
                }

                return $this->templateManager->render(
                    'vpnPortalZeroTier',
                    [
                        'networks' => $networks,
                        'guestNetworks' => $guestNetworks,
                        'userGroups' => $userGroups,
                    ]
                );
            },
            $userAuth
        );

        $service->post(
            '/zerotier/network',
            function (Request $request, UserInfoInterface $u) {
                // XXX validate name
                $networkName = $request->getPostParameter('name');
                // XXX validate groupId
                $groupId = $request->getPostParameter('groupId');

                $networkId = $this->vpnServerApiClient->addZeroTierNetwork($u->getUserId(), $networkName, $groupId);

                return new RedirectResponse($request->getUrl()->getRootUrl().'zerotier', 302);
            },
            $userAuth
        );

        $service->post(
            '/zerotier/client',
            function (Request $request, UserInfoInterface $u) {
                // XXX validate
                $clientId = $request->getPostParameter('client_id');

                $this->vpnServerApiClient->registerZeroTierClient($u->getUserId(), $clientId);

                return new RedirectResponse($request->getUrl()->getRootUrl().'account', 302);
            },
            $userAuth
        );
    }

    private function getConfig(Request $request, $userId, $configName, $poolId)
    {
        Utils::validateConfigName($configName);
        Utils::validatePoolId($poolId);

        // userId + configName length cannot be longer than 64 as the
        // certificate CN cannot be longer than 64
        if (64 < strlen($userId) + strlen($configName) + 1) {
            throw new BadRequestException(
                sprintf('commonName length MUST not exceed %d', 63 - strlen($userId))
            );
        }

        // make sure the configuration does not exist yet
        // XXX: this should be optimized a bit...
        $certList = $this->vpnConfigApiClient->getCertList($userId);
        foreach ($certList['items'] as $cert) {
            if ($configName === $cert['name']) {
                return $this->templateManager->render(
                    'vpnPortalErrorConfigExists',
                    array(
                        'configName' => $configName,
                    )
                );
            }
        }

        $certData = $this->vpnConfigApiClient->addConfiguration($userId, $configName);
        $serverPools = $this->vpnServerApiClient->getServerPools();

        $serverPool = null;
        foreach ($serverPools as $pool) {
            if ($poolId === $pool['id']) {
                $serverPool = $pool;
            }
        }
        if (is_null($serverPool)) {
            throw new BadRequestException('chosen pool does not exist');
        }

        // XXX if 2FA is required, we should warn the user to first enroll!

        $remoteEntities = [];
        foreach ($serverPool['instances'] as $instance) {
            $remoteEntities[] = [
                'port' => $instance['port'],
                'proto' => $instance['proto'],
                'host' => $serverPool['hostName'],
            ];
        }

        $remoteEntities = ['remote' => $remoteEntities];

        $clientConfig = new ClientConfig();
        $vpnConfig = implode(PHP_EOL, $clientConfig->get(array_merge(['twoFactor' => $serverPool['twoFactor']], $certData['certificate'], $remoteEntities)));

        // return an OVPN file
        $response = new Response(200, 'application/x-openvpn-profile');
        $response->setHeader('Content-Disposition', sprintf('attachment; filename="%s.ovpn"', $configName));
        $response->setBody($vpnConfig);

        return $response;
    }

    private function disableConfig($userId, $configName)
    {
        Utils::validateConfigName($configName);

        $this->vpnServerApiClient->disableCommonName($userId.'_'.$configName);

        // disconnect the client
        $this->vpnServerApiClient->killCommonName(sprintf('%s_%s', $userId, $configName));
    }

    public static function validateOtpSecret($otpSecret)
    {
        if (0 === preg_match('/^[A-Z0-9]{16}$/', $otpSecret)) {
            throw new BadRequestException('invalid OTP secret format');
        }
    }

    public static function validateOtpKey($otpKey)
    {
        if (0 === preg_match('/^[0-9]{6}$/', $otpKey)) {
            throw new BadRequestException('invalid OTP key format');
        }
    }

    private static function idToName(array $userGroups, $groupId)
    {
        foreach ($userGroups as $userGroup) {
            if ($userGroup['id'] === $groupId) {
                return $userGroup['displayName'];
            }
        }

        return $groupId;
    }
}
