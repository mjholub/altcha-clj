(ns altcha-clj.encoding 
  (:require
   [clojure.string :as str]
   #?(:clj [cheshire.core :as json]
      )
   ) 
  (:import
   #?(:clj [java.net URLEncoder URLDecoder])
   [java.util Base64]))

#?(:clj
(defn encode-params 
  "Encodes the challenge parameters as an URL (using `URLEncoder`)"
  [params]
  (str/join "&" (for [[k v] params]
                  (str (URLEncoder/encode (name k) "UTF-8")
                       "="
                       (URLEncoder/encode (str v) "UTF-8")
                       )
                  ))
  )
:cljs (defn encode-params 
  "Encodes the challenge parameters as a URL (using `URLSearchParams`)"
  [params]
  (-> (js/URLSearchParams.)
      (doto (fn [search-params]
              (doseq [[k v] params]
                (.append search-params (name k) (str v)))))
      (.toString)))
)

(defn decode-url-component [component]
  #?(:clj (URLDecoder/decode component "UTF-8")
     :cljs (js/decodeURIComponent component)
     )
  )

(defn extract-params 
  "Extracts the URL-encoded parameters map from the salt"
  [salt]
  (into {}
        (map 
          (fn [[k v]] [(keyword k) v])
            (map #(str/split % #"=") (str/split salt #"\&"))))
    )

(defn decode-base64 
  "Cross platform helper function for decoding base64"
  [payload]
  #?(:clj (String. (.decode (Base64/getDecoder) payload))
     :cljs (js/btoa payload)
     )
  )

(defn json->clj 
  "Converts a JSON string to a corresponding Clojure object.
  ClojureScript implementation uses the native JSON.parse
  JVM version uses Cheshire."
  [json-str]
  #?(:clj (json/parse-string json-str)
    :cljs (js->clj (js/JSON.parse json-str) :keywordize-keys true)
  ))
