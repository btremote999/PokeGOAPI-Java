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

package com.pokegoapi.util.hash.pokehash;

import com.pokegoapi.exceptions.hash.HashException;
import com.pokegoapi.exceptions.hash.HashLimitExceededException;
import com.pokegoapi.util.hash.Hash;
import com.pokegoapi.util.hash.HashProvider;
import com.pokegoapi.util.hash.crypto.Crypto;
import com.pokegoapi.util.hash.crypto.PokeHashCrypto;
import com.squareup.moshi.Moshi;
import com.squareup.moshi.Moshi.Builder;

import net.iharder.Base64;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;

import lombok.Getter;

/**
 * Hash provider on latest version, using the PokeHash hashing service.
 * This requires a key and is not free like the legacy provider.
 */
public class PokeHashProvider implements HashProvider {
    //	private static final String HASH_ENDPOINT = "https://pokehash.buddyauth.com/api/v121_2/hash";
    private static final String HASH_ENDPOINT = "https://pokehash.buddyauth.com/api/v121_2/hash";

    private static final int VERSION = 5100;
    private static final long UNK25 = -8832040574896607694L;

    private static final Moshi MOSHI = new Builder().build();

    private final String key;
    private final String endPoint;
    private final HashApiCounterListener listener;

    /**
     * Creates a PokeHashProvider with the given key
     *
     * @param key      the key for the PokeHash API
     * @param endPoint End Point of Poke Api Hash service
     * @param listener Listener of Hash Api response
     */
    public PokeHashProvider(String key, String endPoint, HashApiCounterListener listener) {
        this.key = key;
        this.endPoint = endPoint;
        this.listener = listener;
        if (key == null) {
            throw new IllegalArgumentException("Key cannot be null!");
        }
    }

    @Override
    public Crypto getCrypto() {
        return PokeHashCrypto.POKE_HASH;
    }

    @Override
    public int getHashVersion() {
        return VERSION;
    }

    @Override
    public long getUNK25() {
        return UNK25;
    }

    @Override
    public Hash provide(long timestamp, double latitude, double longitude, double altitude, byte[] authTicket,
                        byte[] sessionData, byte[][] requests) throws HashException {
        Request request = new Request(latitude,
                                      longitude,
                                      altitude,
                                      timestamp,
                                      authTicket,
                                      sessionData,
                                      requests);
        try {
//			HttpsURLConnection connection = (HttpsURLConnection) new URL(HASH_ENDPOINT).openConnection();
            HttpsURLConnection connection = (HttpsURLConnection) new URL(this.endPoint).openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("X-AuthToken", key);
            connection.setRequestProperty("content-type", "application/json");
            connection.setDoOutput(true);

            String requestJSON = MOSHI.adapter(Request.class).toJson(request);
            DataOutputStream out = new DataOutputStream(connection.getOutputStream());
            out.writeBytes(requestJSON);
            out.flush();
            out.close();

            int responseCode = connection.getResponseCode();

            String error = getError(connection);

            switch (responseCode) {
                case HttpURLConnection.HTTP_OK:
                    BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                    StringBuilder builder = new StringBuilder();
                    String line;
                    while ((line = in.readLine()) != null) {
                        builder.append(line);
                    }
                    in.close();
                    Response response = MOSHI.adapter(Response.class).fromJson(builder.toString());
                    long locationAuth = response.getLocationAuthHash();
                    long location = response.getLocationHash();
                    int locationAuthHash = (int) ((locationAuth & 0xFFFFFFFFL) ^ (locationAuth >>> 32));
                    int locationHash = (int) ((location & 0xFFFFFFFFL) ^ (location >>> 32));
                    if (this.listener != null) {
                        this.listener.hashSuccess(System.currentTimeMillis() - timestamp);
                    }
                    return new Hash(locationAuthHash, locationHash, response.getRequestHashes());
                case HttpURLConnection.HTTP_BAD_REQUEST:
                    if (error.length() > 0) {
                        if (this.listener != null) {
                            this.listener.hashFailed(System.currentTimeMillis() - timestamp,
                                                     HttpURLConnection.HTTP_BAD_REQUEST, error);
                        }

                        throw new HashException(error);
                    }
                    if (this.listener != null) {
                        this.listener.hashFailed(System.currentTimeMillis() - timestamp,
                                                 HttpURLConnection.HTTP_BAD_REQUEST,
                                                 "Bad hash request!");
                    }
                    throw new HashException("Bad hash request!");
                case HttpURLConnection.HTTP_UNAUTHORIZED:
                    if (error.length() > 0) {
                        if (this.listener != null) {
                            this.listener.hashFailed(System.currentTimeMillis() - timestamp,
                                                     HttpURLConnection.HTTP_UNAUTHORIZED,
                                                     error);
                        }

                        throw new HashException(error);
                    }
                    if (this.listener != null) {
                        this.listener.hashFailed(System.currentTimeMillis() - timestamp,
                                                 HttpURLConnection.HTTP_UNAUTHORIZED,
                                                 "Unauthorized hash request!");
                    }
                    throw new HashException("Unauthorized hash request!");
                case 429:
                    if (error.length() > 0) {
                        if (this.listener != null) {
                            this.listener.hashFailed(System.currentTimeMillis() - timestamp,
                                                     HttpURLConnection.HTTP_UNAUTHORIZED,
                                                     error);
                        }
                        throw new HashLimitExceededException(error);
                    }

                    if (this.listener != null) {
                        this.listener.hashFailed(System.currentTimeMillis() - timestamp,
                                                 HttpURLConnection.HTTP_UNAUTHORIZED,
                                                 "Exceeded hash limit!");
                    }

                    throw new HashLimitExceededException("Exceeded hash limit!");
                default:
                    if (error.length() > 0) {
                        if (this.listener != null) {
                            this.listener.hashFailed
                                    (System.currentTimeMillis() - timestamp,
                                     204,
                                     error);
                        }

                        throw new HashException(error + " (" + responseCode + ")");
                    }
                    if (this.listener != null) {
                        this.listener.hashFailed
                                (System.currentTimeMillis() - timestamp,
                                 204,
                                 "Received unknown response code! (" + responseCode + ")");
                    }
                    throw new HashException("Received unknown response code! (" + responseCode + ")");
            }
        } catch (IOException e) {
            if (this.listener != null) {
                this.listener.hashFailed(System.currentTimeMillis() - timestamp,
                                         205,
                                         e.getMessage());
            }

            throw new HashException("Failed to perform PokeHash request", e);
        }
    }

    private String getError(HttpURLConnection connection) throws IOException {
        if (connection.getErrorStream() != null) {
            BufferedReader error = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
            StringBuilder builder = new StringBuilder();
            String line;
            while ((line = error.readLine()) != null) {
                builder.append(line);
            }
            error.close();
            return builder.toString();
        }
        return "";
    }

    public interface HashApiCounterListener {
        void hashFailed(long time_spend_ms, int err_no, String err_msg);

        void hashSuccess(long time_spend_ms);
    }

    private static class Response {
        @Getter
        private long locationAuthHash;
        @Getter
        private long locationHash;
        @Getter
        private List<Long> requestHashes;
    }

    private static class Request {
        @Getter
        private double latitude;
        @Getter
        private double longitude;
        @Getter
        private double altitude;
        @Getter
        private long timestamp;
        @Getter
        private String authTicket;
        @Getter
        private String sessionData;
        @Getter
        private String[] requests;

        private Request(double latitude, double longitude, double altitude, long timestamp, byte[] authTicket,
                        byte[] sessionData, byte[][] requests) {
            this.latitude = latitude;
            this.longitude = longitude;
            this.altitude = altitude;
            this.timestamp = timestamp;
            this.authTicket = Base64.encodeBytes(authTicket);
            this.sessionData = Base64.encodeBytes(sessionData);
            this.requests = new String[requests.length];
            for (int i = 0; i < requests.length; i++) {
                this.requests[i] = Base64.encodeBytes(requests[i]);
            }
        }
    }
}
