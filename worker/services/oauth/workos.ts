/**
 * WorkOS OAuth Provider
 * Implements WorkOS AuthKit OAuth 2.0 authentication
 */

import { BaseOAuthProvider } from './base';
import type { OAuthUserInfo } from '../../types/auth-types';
import { OAuthProvider } from '../../types/auth-types';
import { createLogger } from '../../logger';

const logger = createLogger('WorkOSOAuth');

/**
 * WorkOS OAuth Provider implementation
 */
export class WorkOSOAuthProvider extends BaseOAuthProvider {
    protected readonly provider: OAuthProvider = 'workos';
    protected readonly authorizationUrl = 'https://api.workos.com/user_management/authorize';
    protected readonly tokenUrl = 'https://api.workos.com/user_management/authenticate';
    protected readonly userInfoUrl = ''; // WorkOS returns user info in token response
    protected readonly scopes: string[] = [];

    /**
     * Override getAuthorizationUrl for WorkOS-specific params
     */
    async getAuthorizationUrl(state: string, codeVerifier?: string): Promise<string> {
        const params = new URLSearchParams({
            client_id: this.clientId,
            redirect_uri: this.redirectUri,
            response_type: 'code',
            state,
            provider: 'authkit',
        });

        if (codeVerifier) {
            const challenge = await this.generateCodeChallenge(codeVerifier);
            params.append('code_challenge', challenge);
            params.append('code_challenge_method', 'S256');
        }

        return `${this.authorizationUrl}?${params.toString()}`;
    }

    /**
     * Override exchangeCodeForTokens for WorkOS API format
     */
    async exchangeCodeForTokens(code: string, codeVerifier?: string) {
        try {
            const body: Record<string, string> = {
                grant_type: 'authorization_code',
                code,
                client_id: this.clientId,
            };

            if (codeVerifier) {
                body.code_verifier = codeVerifier;
            }

            const response = await fetch('https://api.workos.com/user_management/authenticate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.clientSecret}`,
                },
                body: JSON.stringify(body),
            });

            if (!response.ok) {
                const error = await response.text();
                logger.error('WorkOS token exchange failed', { error });
                throw new Error(`Token exchange failed: ${error}`);
            }

            const data = await response.json() as {
                access_token: string;
                refresh_token?: string;
                user: {
                    id: string;
                    email: string;
                    first_name?: string;
                    last_name?: string;
                    profile_picture_url?: string;
                    email_verified: boolean;
                };
            };

            // Store user data for getUserInfo
            this._userData = data.user;

            return {
                accessToken: data.access_token,
                refreshToken: data.refresh_token,
                tokenType: 'Bearer' as const,
            };
        } catch (error) {
            logger.error('Error exchanging code for tokens', error);
            throw error;
        }
    }

    private _userData: {
        id: string;
        email: string;
        first_name?: string;
        last_name?: string;
        profile_picture_url?: string;
        email_verified: boolean;
    } | null = null;

    /**
     * Get user info — WorkOS returns it in the token response
     */
    async getUserInfo(_accessToken: string): Promise<OAuthUserInfo> {
        if (this._userData) {
            return {
                id: this._userData.id,
                email: this._userData.email,
                name: [this._userData.first_name, this._userData.last_name].filter(Boolean).join(' ') || undefined,
                picture: this._userData.profile_picture_url,
                emailVerified: this._userData.email_verified,
            };
        }

        // Fallback: call WorkOS user info endpoint
        try {
            const response = await fetch('https://api.workos.com/user_management/users/me', {
                headers: {
                    'Authorization': `Bearer ${_accessToken}`,
                },
            });

            if (!response.ok) {
                throw new Error('Failed to get user info from WorkOS');
            }

            const data = await response.json() as {
                id: string;
                email: string;
                first_name?: string;
                last_name?: string;
                profile_picture_url?: string;
                email_verified: boolean;
            };

            return {
                id: data.id,
                email: data.email,
                name: [data.first_name, data.last_name].filter(Boolean).join(' ') || undefined,
                picture: data.profile_picture_url,
                emailVerified: data.email_verified,
            };
        } catch (error) {
            logger.error('Error getting user info', error);
            throw error;
        }
    }

    /**
     * Create WorkOS OAuth provider instance
     */
    static create(env: Env, baseUrl: string): WorkOSOAuthProvider {
        if (!env.WORKOS_CLIENT_ID || !env.WORKOS_API_KEY) {
            throw new Error('WorkOS credentials not configured');
        }

        const redirectUri = `${baseUrl}/api/auth/callback/workos`;

        return new WorkOSOAuthProvider(
            env.WORKOS_CLIENT_ID,
            env.WORKOS_API_KEY,
            redirectUri
        );
    }
}
