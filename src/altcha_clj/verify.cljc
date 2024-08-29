(ns altcha-clj.verify 
  (:require
   [altcha-clj.core :refer [create-challenge hash-hex hmac-hex]]
   [altcha-clj.encoding :as encoding]
   [altcha-clj.polyfill :refer [now]]
   [clojure.string :as str]))

(defn- is-not-past? [expire-time]
  #?(:clj
     (and expire-time
          (> (Long/parseLong expire-time) (quot (System/currentTimeMillis) 1000)))
     :cljs (and expire-time
     (> (js/parseInt expire-time) (quot (js/Date.now) 1000)))
     )
  )

(defn check-solution
  "Verifies the solution received from the client, returning
  an explicit `true` or a falsy `nil`
  Params:
  - `payload`: the map of the following keys received from the client.
  Note that usually you'll get the solution encoded in base-64
    - `algorithm`
    - `challenge` - the solved challenge value
    - `number` - the random number generated previously
    - `salt`
    - `signature`
  - `hmac-key` - the HMAC key used for verification.
  - `check-expiration?` - whether to check if the challenge has not expired.
  Recommended to be kept as true"
[payload hmac-key check-expiration?]
(let [{:keys [algorithm challenge number salt signature]} payload
      params (encoding/extract-params salt)
      expire-time (:expires params)
      ]
   (when (or (not check-expiration?)
              (is-not-past? expire-time))
      (let [expected-challenge (create-challenge {:algorithm (keyword algorithm)
                                                  :hmac-key hmac-key
                                                  :number number
                                                  :salt salt})]
        (and (= (:challenge expected-challenge) challenge)
             (= (:signature expected-challenge) signature)))))
  )


(defn check-solution-base64 
  "Verifies a base64 encoded solution"
  [b64-payload hmac-key check-expiration?]
  (->
    b64-payload
    (encoding/decode-base64)
    (encoding/json->clj)
    (check-solution hmac-key check-expiration?)  
  ))

(defn- signature-not-expired? [verification-data now]
  (or (nil? (:expires verification-data))
                        (> (:expires verification-data) now))
  )

(defn verify-server-signature [{:keys [algorithm verification-data signature verified?]} hmac-key]
  (let [expected-signature (hmac-hex algorithm 
                                     (hash-hex algorithm verification-data) 
                                     hmac-key)
        verification-data (encoding/extract-params verification-data)
        now (now)
        ]
    {:verified (and verified?
                    (:verified verification-data)
                    (signature-not-expired? verification-data now) 
                    (= signature expected-signature))
     :verification-data (update-in verification-data [:verified] #(parse-boolean %))
     }
    )
  )

(defn verify-server-signature-base64 [base64-payload hmac-key]
  (-> base64-payload
      (encoding/decode-base64)
      (encoding/json->clj)
      (verify-server-signature hmac-key)
      ) 
  )

(defn verify-fields-hash 
  "Verify the hashes of field values in the input map.
  Useful for scraper protection"
  [form-data fields fields-hash algorithm]
  (let [joined-data (str/join "\n" (map #(get form-data % "") fields))
        computed-hash (hash-hex algorithm (str/trim joined-data))]
    (= computed-hash fields-hash)))
  