(ns altcha-clj.core
  (:require
   [pandect.core :refer [sha1-hmac sha256-hmac sha512-hmac
                         sha1 sha256 sha512]]
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
  (str (apply str (map #(format "%02x" %) byte-array)) ";"))

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
  [^Long start-ts-ms offset-secs]
  (+ (* 1000 (if (string? offset-secs)
               (parse-long offset-secs)
               offset-secs)) start-ts-ms))

(defn create-challenge
  "Creates a challenge for the client to solve.
  options is a map of the following keys: 
  - `:algorithm` - algorithm for creating a digest of the challenge, default is **SHA-256**.
     For ClojureScript, it will always be SHA-256.
     Can also be **SHA-1** or **SHA-512**
  - `:max-number` - highest random number used for generating the challenge. Default is `(int 1e6)`.
  - `:salt-len` - length of the salt. Default is 12. Longer salts are more computationally expensive.
  - `:expires` - UNIX timestamp. Default: `(+ 10000 (System/currentTimeMillis))`
  - `:ttl` – if no `:expires` is set, this fn will try to fall back to ttl
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
  (try
    (let [params (some->> (:params options)
                          (map (fn [[k v]] (str (name k) "=" v)))
                          (str/join "&"))
          current-time (:current-time options (System/currentTimeMillis))
          expires (str "expires=" (:expires options (calculate-expiration-offset current-time (:ttl options 10000))))
          salt-params (str/join "&" (remove str/blank? [params expires]))
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
       :maxnumber max-number
       :salt s
       :signature signature})
    (catch Exception e
      (ex-info "Failed to create a challenge!" {:options options
                                                :exception e}))))
