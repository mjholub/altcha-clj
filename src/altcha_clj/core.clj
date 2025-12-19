(ns altcha-clj.core
  (:require
   [pandect.core :refer [sha1-hmac sha256-hmac sha512-hmac
                         sha1 sha256 sha512]]
   [altcha-clj.time :refer [now]]
   [clojure.string :as str])
  (:import [javax.crypto Mac]
           [javax.crypto.spec SecretKeySpec]))

(defn- hmac-dispatcher
  "Clojure (JVM) function for selecting the appropriate HMAC signing function
  from the pandect library"
  [alg-name data hmac-key]
  (case alg-name
    "SHA-1" (sha1-hmac data hmac-key)
    "SHA-256" (sha256-hmac data hmac-key)
    "SHA-512" (sha512-hmac data hmac-key)
    (throw (ex-info "Invalid algorithm!" {:got alg-name
                                          :want #{"SHA-1" "SHA-256" "SHA-512"}}))))

(defn random-bytes [^Long n]
  (let [bytes (byte-array n)]
    (.nextBytes (java.security.SecureRandom.) bytes)
    bytes))

(defn- ab2hex
  "Converts a byte array to a hexadecimal string"
  [byte-array]
  (apply str (map #(format "%02x" %) byte-array)))

(defn random-int [^Long max]
  (.nextInt (java.security.SecureRandom.) max))

(defn hash-hex
  "Generates a hexadecimal string representation of the challenge
     message digest created using the selected algorithm"
  [^String algorithm data]
  (case algorithm
    "SHA-1" (sha1 data)
    "SHA-256" (sha256 data)
    "SHA-512" (sha512 data)))

(defn- secret-key-inst [key mac]
  (SecretKeySpec. (.getBytes key "UTF-8") (.getAlgorithm mac)))

(defn hmac-hex
  "Returns the HMAC-encoded value of the data. Params
    - `algorithm` - 'SHA-256', 'SHA-512' or 'SHA-1'
    - `data` – the data to be hashed
    - `key` – the private HMAC key"
  [algorithm data key]
  (hmac-dispatcher algorithm data key))

(defn calculate-expiration-offset
  "Adds `offset-secs` * 1000 to the `start-ts-ms` timestamp value"
  [start-ts-ms offset-secs]
  (+ (* 1000 (parse-long offset-secs)) start-ts-ms))

(defn create-challenge
  "Creates a challenge for the client to solve.
  options is a map of the following keys: 
  - `:algorithm` - algorithm for creating a digest of the challenge, default is **SHA-256**.
     For ClojureScript, it will always be SHA-256.
     Can also be **SHA-1** or **SHA-512**
  - `:max-number` - highest random number used for generating the challenge. Default is `(int 1e6)`.
  - `:salt-len` - length of the salt. Default is 12. Longer salts are more computationally expensive.
  - `:expires` - optional timestamp. This value will be implicitly bound if `ttl` 
  is present 
  by calling `calculate-expiration-offset`. See below. Usually you'll only need to set `ttl`
  - `:ttl` - Time-to-live in seconds. Needed for calculating challenge expiration time.
  You don't need to convert a string value to an integer here, it'll be converted for you.
  Note the difference between `ttl` and `expires`. Expires is returned by the handler,
  while ttl must be present in the challenge response salt to compare the hashes
  of the challenge in the initial challenge and the challenge response.
  `current-time-ms` is platform-specfic pseudocode placeholder here
  - `:current-time` - current UNIX millisecond timestamp.
    Pass this argument to make the calculation of challenge expiration more 
    deterministic. Otherwise it will be generated as a side effect inside `create-challenge`
  - `:hmac-key` - required, the secret key for creating the HMAC signature (a string value, not a path)
  - `:params` - optional, additional parameters to include in the salt

  Changing the following parameters to hardcoded values is not recommended outside development settings:
  - `:current-time`
  - `:salt` - optional, custom salt to use instead of generating one
  Used for validation
  - `:number` - optional, custom number to use instead of generating one
  "
  [{:keys [algorithm max-number salt salt-len]
    :or {algorithm "SHA-256" max-number (int 1e6) salt-len 12}
    :as options}]
  (let [params (some->> (:params options)
                        (map (fn [[k v]] (str (name k) "=" v)))
                        (str/join "&"))
        ttl (some->> options :ttl (str "ttl="))
        current-time (get options :current-time (now))
        ;; use 'expires as override and fall back to ttl if none present'
        expires (when-let [e (:ttl options)]
                  (str "expires=" (:expires options (calculate-expiration-offset current-time e))))
        salt-params (str/join "&" (remove str/blank? [params expires ttl]))
        ;; use the pre-computed salt. if params are present, append them after 
        ;; a question mark with '&' separators
        s (if-not (str/blank? salt)
            (str salt
                 (when-not (str/ends-with? salt ";") ";") ;; Add a delimiter to prevent parameter splicing
                 (when-not (str/blank? salt-params) (str "?" salt-params)))
               ;; generate a random salt
            (let [random-salt (ab2hex (random-bytes salt-len))]
              (if (str/blank? salt-params)
                random-salt
                (str random-salt "?" salt-params))))
        number (:number options (random-int max-number))
        challenge (hash-hex algorithm (str s number))
        signature (hmac-hex algorithm challenge (:hmac-key options))]
    {:algorithm algorithm
     :challenge challenge
     :created-at current-time
     :maxnumber max-number
     :salt s
     :signature signature}))
