<?php

declare(strict_types=1);
/**
 * GoogleAuth for FOSSBilling.
 *
 * Copyright 2026 Web Boomers (https://www.webboomers.in)
 * SPDX-License-Identifier: MIT
 */

namespace Box\Mod\Googleauth\Controller;

use Box\Mod\Googleauth\Service;
use FOSSBilling\InformationException;
use Symfony\Component\HttpFoundation\Response;

/**
 * The administration side: one settings page.
 *
 * FOSSBilling already links to `/extension/settings/googleauth` from the
 * extensions list (because `templates/admin/mod_googleauth_settings.html.twig`
 * exists); this controller adds the same page under Settings so it is easy to
 * find, and enforces the module's `manage_settings` permission on the way in.
 */
class Admin implements \FOSSBilling\InjectionAwareInterface
{
    protected ?\Pimple\Container $di = null;

    public function setDi(\Pimple\Container $di): void
    {
        $this->di = $di;
    }

    public function getDi(): ?\Pimple\Container
    {
        return $this->di;
    }

    /**
     * @return array<string, mixed>
     */
    public function fetchNavigation(): array
    {
        return [
            'subpages' => [
                [
                    'location' => 'system',
                    'label' => __trans('Google Authentication'),
                    'index' => 1600,
                    'uri' => $this->di['url']->adminLink('googleauth'),
                    'class' => '',
                ],
            ],
        ];
    }

    public function register(\Box_App &$app): void
    {
        $app->get('/googleauth', 'get_index', [], static::class);
    }

    public function get_index(\Box_App $app): string|Response
    {
        $this->di['is_admin_logged'];

        try {
            $this->di['mod_service']('extension')->hasManagePermission(Service::MODULE_NAME);
        } catch (InformationException $e) {
            return $app->errorResponse($e, 403);
        }

        return $app->render('mod_googleauth_settings');
    }
}
