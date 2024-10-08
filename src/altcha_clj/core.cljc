(ns altcha-clj.core
  (:refer-clojure :exclude [empty?])
  (:require
   #?(:cljs [goog.crypt :as crypt]
      :clj [pandect.core :refer [sha1-hmac sha256-hmac sha512-hmac
                                  sha1 sha256 sha512]]
      )
   [altcha-clj.polyfill :refer [now parse-int]]
   [clojure.string :as str])
            #?(:cljs (:import
                      [goog.crypt Hmac Sha256]

                      )
               :clj (:import [javax.crypto Mac]
                             [javax.crypto.spec SecretKeySpec]
                             )
               ))

(def ^:private ^:const default-max-number (int 1e6))
(def ^:private ^:const default-salt-len 12)
(def ^:private ^:const default-alg "SHA-256") ;; or SHA-1/SHA-512

;; false negative, used in hmac-hex
#_{:clj-kondo/ignore [:unused-private-var]} 
#?(:clj (defn- hmac-dispatcher
  "Clojure (JVM) function for selecting the appropriate HMAC signing function
  from the pandect library"
  [alg-name data hmac-key]
  (case alg-name
    "SHA-1" (sha1-hmac data hmac-key)
    "SHA-256" (sha256-hmac data hmac-key)
    "SHA-512" (sha512-hmac data hmac-key)
    (throw (ex-info "Invalid algorithm!" {:got alg-name
                                          :want #{"SHA-1" "SHA-256" "SHA-512"}}))
    )
  ))

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
     (case algorithm 
       "SHA-1" (sha1 data)
       "SHA-256" (sha256 data)
       "SHA-512" (sha512 data)
       ))
   :cljs
   (defn hash-hex
    "Generates a hexadecimal string representation of the SHA-256 digest of the challenge message"
     [_ data]
     (let [sha256 (Sha256.)
           data-bytes (crypt/stringToUtf8ByteArray data)]
       (.update sha256 data-bytes)
       (ab2hex (.digest sha256)))))

#?(:clj (defn- secret-key-inst [key mac]
  (SecretKeySpec. (.getBytes key "UTF-8") (.getAlgorithm mac))
  )
)

#?(:clj
   (defn hmac-hex
    "Returns the HMAC-encoded value of the data. Params
    - `algorithm` - 'SHA-256', 'SHA-512' or 'SHA-1'"
     [algorithm data key]
    (hmac-dispatcher algorithm data key)
     )
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

  Changing the following parameters to hardcoded values is not recommended outside development settings
  - `:salt` - optional, custom salt to use instead of generating oneo
  Used for validation
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
        current-time (get options :current-time (now))
        expires (when-let [e (:ttl options)]
          (if-let [exp-override (:expires options)]
          (str "expires=" exp-override)
          (str "expires=" (calculate-expiration-offset current-time e))))
        salt-params (str/join "&" (remove str/blank? [params expires ttl]))
        salt (if-let [s (:salt options)]
               ;; use the pre-computed salt. if params are present, append them after 
               ;; a question mark with '&' separators
               (if (str/blank? salt-params) s (str s "?" salt-params))
               ;; generate a random salt
               (let [random-salt (ab2hex (random-bytes salt-len))]
                 (if (str/blank? salt-params)
                   random-salt
                   (str random-salt "?" salt-params))))
        number (or (:number options) (random-int max-number))
        challenge (hash-hex algorithm (str salt number))
        signature (hmac-hex algorithm challenge (:hmac-key options))]
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
