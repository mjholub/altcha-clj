(ns altcha-clj.core
  (:refer-clojure :exclude [empty?])
  (:require
   #?(:cljs [goog.crypt :as crypt])
   [altcha-clj.polyfill :refer [now parse-int]]
   [clojure.string :as str])
            #?(:cljs (:import
                      [goog.crypt Hmac Sha256])))

(def ^:private ^:const default-max-number (int 1e6))
(def ^:private ^:const default-salt-len 12)
(def ^:private ^:const default-alg "SHA-256") ;; or SHA-1/SHA-512

;; false negative, used in hmac-hex
#_{:clj-kondo/ignore [:unused-private-var]} 
(defn- get-hmac-name
  "Helper function to convert JS algorithm name to one known
  to javax.crypto.Mac/getInstance"
  [alg-name]
  (case alg-name
    "SHA-1" "HmacSHA1"
    "SHA-256" "HmacSHA256"
    "SHA-512" "HmacSHA512"
    (throw (ex-info "Invalid algorithm!" {:got alg-name
                                          :want #{"SHA-1" "SHA-256" "SHA-512"}}))
    )
  )

#?(:clj
   (defn random-bytes [n]
     (let [bytes (byte-array n)]
       (.nextBytes (java.security.SecureRandom.) bytes)
       bytes))
   :cljs
   (defn random-bytes [n]
     (let [arr (new js/Uint8Array n)]
       (.getRandomValues js/crypto arr)
       arr)))

#?(:clj
   (defn- ab2hex
    "Converts a byte array to a hexadecimal string"
     [byte-array]
     (apply str (map #(format "%02x" %) byte-array)))
   :cljs
   (defn- ab2hex [array-buffer]
     (crypt/byteArrayToHex array-buffer)))

#?(:clj
   (defn random-int [max]
     (.nextInt (java.security.SecureRandom.) max))
   :cljs
   (defn random-int [max]
     (js/Math.floor (* (js/Math.random) max))))

#?(:clj
   (defn hash-hex 
     "Generates a hexadecimal string representation of the challenge
     message digest created using the selected algorithm"
     [algorithm data]
     (let [md (java.security.MessageDigest/getInstance algorithm)
           hash-bytes (.digest md (.getBytes data "UTF-8"))]
       (ab2hex hash-bytes)))
   :cljs
   (defn hash-hex
    "Generates a hexadecimal string representation of the SHA-256 digest of the challenge message"
     [_ data]
     (let [sha256 (Sha256.)
           data-bytes (crypt/stringToUtf8ByteArray data)]
       (.update sha256 data-bytes)
       (ab2hex (.digest sha256)))))

#?(:clj
   (defn hmac-hex
    "Returns the HMAC-encoded value of the data. Params
    - `algorithm` - 'SHA-256', 'SHA-512' or 'SHA-1'"
     [algorithm data key]
     (let [secret-key (javax.crypto.spec.SecretKeySpec. 
                        (.getBytes key "UTF-8")
                        algorithm)
           mac (javax.crypto.Mac/getInstance (get-hmac-name algorithm))]
       (.init mac secret-key)
       (ab2hex (.doFinal mac (.getBytes data "UTF-8")))))
   :cljs
   (defn hmac-hex [algorithm data key]
     (let [hmac (Hmac. (Sha256.) (crypt/stringToUtf8ByteArray key))
           data-bytes (crypt/stringToUtf8ByteArray data)]
       (ab2hex (.getHmac hmac data-bytes)))))

(defn calculate-expiration-offset
 "Adds `offset-secs` * 1000 to the `start-ts-ms` timestamp value"
  [start-ts-ms offset-secs]
    (+ (* 1000 (parse-int offset-secs)) start-ts-ms))
  

(defn create-challenge 
  "Creates a challenge for the client to solve.
  options is a map of the following keys: 
  - `:algorithm` - algorithm for creating a digest of the challenge, default is **SHA-256**.
     For ClojureScript, it will always be SHA-256.
     Can also be **SHA-1** or **SHA-512**
  - `:max-number` - highest random number used for generating the challenge. Default is 1e6, represented as a fixed point integer.
  - `:salt-len` - length of the salt. Default is 12. Longer salts are more computationally expensive.
  - `:expires` - optional. This value will be implicitly bound if `ttl` 
  is present 
  by calling `calculate-expiration-offset`. See below.
  - `ttl` - Time-to-live in seconds. Needed for calculating challenge expiration time.
  You don't need to convert a string value to an integer here, it'll be converted for you.
  Note the difference between `ttl` and `expires`. Expires is returned by the handler,
  while ttl must be present in the challenge response salt to compare the hashes
  of the challenge in the initial challenge and the challenge response.
  `current-time-ms` is platform-specfic pseudocode placeholder here
  - `current-time` - current UNIX millisecond timestamp.
    Pass this argument to make the calculation of challenge expiration more 
    deterministic. Otherwise it will be generated as a side effect inside `create-challenge`
  - `:hmac-key` - required, the secret key for creating the HMAC signature (a string value, not a path)
  - `:params` - optional, additional parameters to include in the salt

  Changing the following parameters to hardcoded values is not recommended outside development settings
  - `:salt` - optional, custom salt to use instead of generating one
  - `:number` - optional, custom number to use instead of generating one
  "
  [options]
  (let [algorithm (:algorithm options default-alg)
        max-number (:max-number options default-max-number)
        salt-len (:salt-len options default-salt-len)
        params (when-let [p (:params options)]
                 (str/join "&" (map (fn [[k v]] (str (name k) "=" v)) p)))
        ttl (when-let [_ttl (:ttl options)]
              (str "ttl=" (:ttl options)) 
              )
        current-time (get :current-time options (now))
        expires (when-let [e (:expires options)]
          (str "expires=" (calculate-expiration-offset current-time e)))
        salt-params (str/join "&" (remove str/blank? [params expires ttl]))
        salt (if-let [s (:salt options)]
               (if (str/blank? salt-params) s (str s "?" salt-params))
               (let [random-salt (ab2hex (random-bytes salt-len))]
                 (if (str/blank? salt-params)
                   random-salt
                   (str random-salt "?" salt-params))))
        number (or (:number options) (random-int max-number))
        challenge (hash-hex algorithm (str salt number))
        signature (hmac-hex algorithm challenge (:hmac-key options))]
    (println "value for 'expires': " expires)
    {:algorithm algorithm
     :challenge challenge
     :created-at current-time
     :maxnumber max-number
     :salt salt
     :signature signature}))

#?(:cljs
   (defn ^:export createChallenge [options]
     (let [clj-options (js->clj options :keywordize-keys true)]
       (clj->js (create-challenge clj-options)))))
