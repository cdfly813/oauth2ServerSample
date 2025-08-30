export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  scope: string;
}

export interface User {
  username: string;
  roles: string[];
}

class OAuth2Service {
  private readonly OAUTH2_SERVER_URL = 'http://localhost:8080';
  private readonly CLIENT_ID = 'client1';
  private readonly CLIENT_SECRET = 'secret1';
  private readonly REDIRECT_URI = 'http://localhost:3000/callback';

  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  private tokenExpiry: number | null = null;

  constructor() {
    this.loadTokens();
  }

  private loadTokens() {
    const accessToken = localStorage.getItem('access_token');
    const refreshToken = localStorage.getItem('refresh_token');
    const expiry = localStorage.getItem('token_expiry');

    if (accessToken && refreshToken && expiry) {
      this.accessToken = accessToken;
      this.refreshToken = refreshToken;
      this.tokenExpiry = parseInt(expiry);
    }
  }

  private saveTokens(accessToken: string, refreshToken: string, expiresIn: number) {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    this.tokenExpiry = Date.now() + (expiresIn * 1000);

    localStorage.setItem('access_token', accessToken);
    localStorage.setItem('refresh_token', refreshToken);
    localStorage.setItem('token_expiry', this.tokenExpiry.toString());
  }

  private clearTokens() {
    this.accessToken = null;
    this.refreshToken = null;
    this.tokenExpiry = null;

    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('token_expiry');
  }

  isAuthenticated(): boolean {
    return this.accessToken !== null && !this.isTokenExpired();
  }

  isTokenExpired(): boolean {
    return this.tokenExpiry ? Date.now() >= this.tokenExpiry : true;
  }

  getAccessToken(): string | null {
    return this.accessToken;
  }

  initiateLogin(): void {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.CLIENT_ID,
      redirect_uri: this.REDIRECT_URI,
      scope: 'read write',
      state: this.generateState()
    });

    const authUrl = `${this.OAUTH2_SERVER_URL}/oauth2/authorize?${params.toString()}`;
    window.location.href = authUrl;
  }

  async handleCallback(code: string): Promise<TokenResponse> {
    const tokenRequest = new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: this.REDIRECT_URI,
      client_id: this.CLIENT_ID
    });

    const response = await fetch(`${this.OAUTH2_SERVER_URL}/oauth2/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + btoa(`${this.CLIENT_ID}:${this.CLIENT_SECRET}`)
      },
      body: tokenRequest.toString()
    });

    if (!response.ok) {
      throw new Error(`Token exchange failed: ${response.statusText}`);
    }

    const tokenData: TokenResponse = await response.json();
    this.saveTokens(tokenData.access_token, tokenData.refresh_token, tokenData.expires_in);

    return tokenData;
  }

  async refreshAccessToken(): Promise<TokenResponse> {
    if (!this.refreshToken) {
      throw new Error('No refresh token available');
    }

    const tokenRequest = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: this.refreshToken,
      client_id: this.CLIENT_ID
    });

    const response = await fetch(`${this.OAUTH2_SERVER_URL}/oauth2/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + btoa(`${this.CLIENT_ID}:${this.CLIENT_SECRET}`)
      },
      body: tokenRequest.toString()
    });

    if (!response.ok) {
      this.clearTokens();
      throw new Error(`Token refresh failed: ${response.statusText}`);
    }

    const tokenData: TokenResponse = await response.json();
    this.saveTokens(tokenData.access_token, tokenData.refresh_token, tokenData.expires_in);

    return tokenData;
  }

  async authenticatedFetch(url: string, options: RequestInit = {}): Promise<Response> {
    if (!this.isAuthenticated()) {
      throw new Error('Not authenticated');
    }

    if (this.isTokenExpired() || (this.tokenExpiry && Date.now() >= (this.tokenExpiry - 300000))) {
      await this.refreshAccessToken();
    }

    const headers = new Headers(options.headers);
    headers.set('Authorization', `Bearer ${this.accessToken}`);

    const requestOptions: RequestInit = {
      ...options,
      headers
    };

    let response = await fetch(url.startsWith('http') ? url : this.OAUTH2_SERVER_URL + url, requestOptions);

    if (response.status === 401) {
      try {
        await this.refreshAccessToken();
        headers.set('Authorization', `Bearer ${this.accessToken}`);
        response = await fetch(url.startsWith('http') ? url : this.OAUTH2_SERVER_URL + url, requestOptions);
      } catch (error) {
        this.clearTokens();
        throw new Error('Authentication failed, please login again');
      }
    }

    return response;
  }

  logout(): void {
    this.clearTokens();
    window.location.href = '/';
  }

  private generateState(): string {
    return Math.random().toString(36).substring(2, 15);
  }

  getUserInfo(): User | null {
    if (!this.accessToken) return null;

    try {
      const payload = this.accessToken.split('.')[1];
      const decoded = JSON.parse(atob(payload));
      return {
        username: decoded.sub || decoded.username || 'Unknown',
        roles: decoded.roles || decoded.authorities || []
      };
    } catch (error) {
      console.error('Error decoding token:', error);
      return null;
    }
  }
}

export const oauth2Service = new OAuth2Service();