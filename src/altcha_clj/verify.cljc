(ns altcha-clj.verify 
  (:require
   [altcha-clj.encoding :as encoding]
   [altcha-clj.core :refer [create-challenge]]
   ))

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
