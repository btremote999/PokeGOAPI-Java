/*
 *     This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.pokegoapi.auth;

import POGOProtos.Networking.Envelopes.RequestEnvelopeOuterClass.RequestEnvelope.AuthInfo;
import com.pokegoapi.exceptions.request.InvalidCredentialsException;
import com.pokegoapi.exceptions.request.LoginFailedException;
import com.pokegoapi.util.SystemTimeImpl;
import com.pokegoapi.util.Time;
import com.squareup.moshi.Moshi;
import lombok.Setter;
import okhttp3.*;

import java.io.IOException;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class PtcCredentialProvider extends CredentialProvider {
	private static final String USER_AGENT = "pokemongo/1 CFNetwork/811.4.18 Darwin/16.5.0";
	private static final String UNITY_VERSION = "5.5.1f1";

	private static final String LOGIN_URL = "https://sso.pokemon.com/sso/login";
	private static final String SERVICE_URL = "https://sso.pokemon.com/sso/oauth2.0/callbackAuthorize";
	private static final String LOGIN_OAUTH_URL = "https://sso.pokemon.com/sso/oauth2.0/authorize";

	private static final String REDIRECT_URI = "https://www.nianticlabs.com/pokemongo/error";

	private static final String CLIENT_ID = "mobile-app_pokemon-go";
	private static final String HOST = "sso.pokemon.com";
	private static final String EVENT_ID = "submit";
	private static final String LOCALE = "en_US";
	private static final int MAXIMUM_RETRIES = 5;

	protected final OkHttpClient client;
	protected final String username;
	protected final String password;
	protected final Time time;
	protected String tokenId;
	protected long expiresTimestamp;

	protected AuthInfo.Builder authbuilder;

	protected SecureRandom random = new SecureRandom();

	@Setter
	protected boolean shouldRetry = true;

	/**
	 * Instantiates a new Ptc login.
	 *
	 * @param client the client
	 * @param username Username
	 * @param password password
	 * @param time a Time implementation
	 * @throws LoginFailedException if an exception occurs while attempting to log in
	 * @throws InvalidCredentialsException if invalid credentials are used
	 */
	public PtcCredentialProvider(OkHttpClient client, String username, String password, Time time)
			throws LoginFailedException, InvalidCredentialsException {
		this.time = time;
		this.username = username;
		this.password = password;
		/*
		This is a temporary, in-memory cookie jar.
		We don't require any persistence outside of the scope of the login,
		so it being discarded is completely fine
		*/
		CookieJar tempJar = new CookieJar() {
			private final HashMap<String, List<Cookie>> cookieStore = new HashMap<String, List<Cookie>>();

			@Override
			public void saveFromResponse(HttpUrl url, List<Cookie> cookies) {
				cookieStore.put(url.host(), cookies);
			}

			@Override
			public List<Cookie> loadForRequest(HttpUrl url) {
				List<Cookie> cookies = cookieStore.get(url.host());
				return cookies != null ? cookies : new ArrayList<Cookie>();
			}
		};

		this.client = client.newBuilder()
				.cookieJar(tempJar)
				.addInterceptor(new Interceptor() {
					@Override
					public Response intercept(Chain chain) throws IOException {
						//Makes sure the User-Agent is always set
						Request req = chain.request();
						req = req.newBuilder()
								.removeHeader("User-Agent")
								.header("User-Agent", USER_AGENT)
								.header("X-Unity-Version", UNITY_VERSION)
								.header("Host", HOST)
								.header("Connection", "keep-alive")
								.header("Accept-Language", LOCALE.replace("_", "-"))
								.build();
						return chain.proceed(req);
					}
				})
				.build();

		authbuilder = AuthInfo.newBuilder();
		login(username, password, 0);
	}

	/**
	 * Instantiates a new Ptc login.
	 * Deprecated: specify a Time implementation
	 *
	 * @param client the client
	 * @param username Username
	 * @param password password
	 * @throws LoginFailedException if an exception occurs while attempting to log in
	 * @throws InvalidCredentialsException if invalid credentials are used
	 */
	public PtcCredentialProvider(OkHttpClient client, String username, String password)
			throws LoginFailedException, InvalidCredentialsException {
		this(client, username, password, new SystemTimeImpl());
	}

	/**
	 * Starts a login flow for pokemon.com (PTC) using a username and password,
	 * this uses pokemon.com's oauth endpoint and returns a usable AuthInfo without user interaction
	 *
	 * @param username PTC username
	 * @param password PTC password
	 * @param attempt the current attempt index
	 * @throws LoginFailedException if an exception occurs while attempting to log in
	 * @throws InvalidCredentialsException if invalid credentials are used
	 */
	private void login(String username, String password, int attempt)
			throws LoginFailedException, InvalidCredentialsException {

		try {
			Response getResponse;
			try {
				getResponse = client.newCall(new Request.Builder()
						.header("Content-Length", "-1")
						.url(
								HttpUrl.parse(LOGIN_OAUTH_URL).newBuilder()
										.addQueryParameter("client_id", CLIENT_ID)
										.addQueryParameter("redirect_uri", REDIRECT_URI)
										.addQueryParameter("locale", LOCALE)
										.build()
						)
						.get()
						.build()
				)
						.execute();
			} catch (IOException e) {
				throw new LoginFailedException("Failed to receive contents from server", e);
			}

			Moshi moshi = new Moshi.Builder().build();

			PtcAuthJson ptcAuth;
			try {
				String response = getResponse.body().string();
				ptcAuth = moshi.adapter(PtcAuthJson.class).fromJson(response);
			} catch (IOException e) {
				throw new LoginFailedException("Looks like the servers are down", e);
			}

			Response response;
			try {
				response = client.newBuilder()
						.followRedirects(false)
						.followSslRedirects(false)
						.build()
						.newCall(new Request.Builder()
								.header("Content-Type", "application/x-www-form-urlencoded")
								.url(HttpUrl.parse(LOGIN_URL).newBuilder()
										.addQueryParameter("service", SERVICE_URL).build()
								)
								.method("POST", new FormBody.Builder()
										.add("lt", ptcAuth.getLt())
										.add("execution", ptcAuth.getExecution())
										.add("_eventId", EVENT_ID)
										.add("locale", LOCALE)
										.addEncoded("username", URLEncoder.encode(username))
										.addEncoded("password", URLEncoder.encode(password))
										.build()
								)
								.build()
						)
						.execute();
			} catch (IOException e) {
				throw new LoginFailedException("Network failure", e);
			}

			String body;
			try {
				body = response.body().string();
			} catch (IOException e) {
				throw new LoginFailedException("Response body fetching failed", e);
			}

			if (body.length() > 0) {
				PtcError ptcError;
				try {
					ptcError = moshi.adapter(PtcError.class).fromJson(body);
				} catch (IOException e) {
					throw new LoginFailedException("Unmarshalling failure", e);
				}
				if (ptcError.getError() != null && ptcError.getError().length() > 0) {
					throw new LoginFailedException(ptcError.getError());
				} else if (ptcError.getErrors().length > 0) {
					StringBuilder builder = new StringBuilder();
					String[] errors = ptcError.getErrors();
					for (int i = 0; i < errors.length - 1; i++) {
						String error = errors[i];
						builder.append("\"").append(error).append("\", ");
					}
					builder.append("\"").append(errors[errors.length - 1]).append("\"");
					throw new LoginFailedException(builder.toString());
				}
			}

			String ticket = null;
			for (String cookie : response.headers("set-cookie")) {
				if (cookie.contains("CASTGC")) {
					cookie = cookie.substring(cookie.indexOf("CASTGC=") + 7);
					cookie = cookie.substring(0, cookie.indexOf(";"));
					ticket = cookie;
					break;
				}
			}

			if (ticket == null)
				throw new LoginFailedException("Failed to fetch token, body:" + body);

			tokenId = ticket;
			expiresTimestamp = time.currentTimeMillis() + 7195 * 1000;
		} catch (LoginFailedException e) {
			if (shouldRetry && attempt < MAXIMUM_RETRIES) {
				login(username, password, ++attempt);
			} else {
				throw new LoginFailedException("Exceeded maximum login retries", e);
			}
		}
	}

	@Override
	public String getTokenId(boolean refresh) throws LoginFailedException, InvalidCredentialsException {
		if (refresh || isTokenIdExpired()) {
			login(username, password, 0);
		}
		return tokenId;
	}

	/**
	 * Valid auth info object	 *
	 *
	 * @param refresh if this AuthInfo should be refreshed
	 * @return AuthInfo a AuthInfo proto structure to be encapsulated in server requests
	 * @throws LoginFailedException if an exception occurs while attempting to log in
	 * @throws InvalidCredentialsException if invalid credentials are used
	 */
	@Override
	public AuthInfo getAuthInfo(boolean refresh) throws LoginFailedException, InvalidCredentialsException {
		if (refresh || isTokenIdExpired()) {
			login(username, password, 0);
		}

		authbuilder.setProvider("ptc");
		authbuilder.setToken(AuthInfo.JWT.newBuilder().setContents(tokenId).setUnknown2(59).build());

		return authbuilder.build();
	}

	@Override
	public boolean isTokenIdExpired() {
		return time.currentTimeMillis() > expiresTimestamp;
	}

	@Override
	public void reset() {
		tokenId = null;
		expiresTimestamp = 0;
	}
}