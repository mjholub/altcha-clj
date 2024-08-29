(ns altcha-clj.core
  (:refer-clojure :exclude [empty?])
  (:require [clojure.string :as str]
            #?(:cljs [goog.crypt :as crypt])
            )
            #?(:cljs (:import [goog.crypt Sha256 Hmac])))

(def default-max-number 1e6)
(def default-salt-len 12)
(def default-alg "SHA-256") ;; or SHA-1/SHA-512

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
   (defn ab2hex [byte-array]
     (apply str (map #(format "%02x" %) byte-array)))
   :cljs
   (defn ab2hex [array-buffer]
     (crypt/byteArrayToHex array-buffer)))

#?(:clj
   (defn random-int [max]
     (.nextInt (java.security.SecureRandom.) max))
   :cljs
   (defn random-int [max]
     (js/Math.floor (* (js/Math.random) max))))

#?(:clj
   (defn hash-hex [algorithm data]
     (let [md (java.security.MessageDigest/getInstance algorithm)
           hash-bytes (.digest md (.getBytes data "UTF-8"))]
       (ab2hex hash-bytes)))
   :cljs
   (defn hash-hex [algorithm data]
     (let [sha256 (Sha256.)
           data-bytes (crypt/stringToUtf8ByteArray data)]
       (.update sha256 data-bytes)
       (ab2hex (.digest sha256)))))

#?(:clj
   (defn hmac-hex [algorithm data key]
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

(defn create-challenge 
  "Creates a challenge for the client to solve.
  options is a map of the following keys: 
  - :algorithm - algorithm for creating a digest of the challenge, default is SHA-256
  - :max-number - highest random number used for generating the challenge. Default is 1e6
  - :salt-len - length of the salt. Default is 12
  - :expires - optional, recommended expiration time of the challenge validity in seconds
  - :hmac-key - required, the secret key for creating the HMAC signature
  - :salt - optional, custom salt to use instead of generating one
  - :number - optional, custom number to use instead of generating one
  - :params - optional, additional parameters to include in the salt
  "
  [options]
  (let [algorithm (:algorithm options default-alg)
        max-number (:max-number options default-max-number)
        salt-len (:salt-len options default-salt-len)
        params (when-let [p (:params options)]
                 (str/join "&" (map (fn [[k v]] (str (name k) "=" v)) p)))
        expires (when-let [e (:expires options)]
                  (str "expires=" #?(:clj (quot (.getTime e) 1000)
                                     :cljs (js/Math.floor (/ (.getTime e) 1000)))))
        salt-params (str/join "&" (remove str/blank? [params expires]))
        salt (if-let [s (:salt options)]
               (if (str/blank? salt-params) s (str s "?" salt-params))
               (let [random-salt (ab2hex (random-bytes salt-len))]
                 (if (str/blank? salt-params)
                   random-salt
                   (str random-salt "?" salt-params))))
        number (or (:number options) (random-int max-number))
        challenge (hash-hex algorithm (str salt number))
        signature (hmac-hex algorithm challenge (:hmac-key options))]
    {:algorithm algorithm
     :challenge challenge
     :maxnumber max-number
     :salt salt
     :signature signature}))

#?(:cljs
   (defn ^:export createChallenge [options]
     (let [clj-options (js->clj options :keywordize-keys true)]
       (clj->js (create-challenge clj-options)))))
