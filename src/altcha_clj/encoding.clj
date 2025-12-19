(ns altcha-clj.encoding
  (:require
   [clojure.string :as str]
   [cheshire.core :as json])
  (:import
   [java.net URLEncoder URLDecoder]
   [java.util Base64]))

(defn encode-params
  "Encodes the challenge parameters as an URL (using `URLEncoder`)"
  [params]
  (str/join "&" (for [[k v] params]
                  (str (URLEncoder/encode (name k) "UTF-8")
                       "="
                       (URLEncoder/encode (str v) "UTF-8")))))

(defn decode-url-component [component]
  (URLDecoder/decode component "UTF-8"))

(defn extract-params
  "Extracts the URL-encoded parameters map from the salt.
  The parameters must be simple types 
  (i.e. numbers, strings, nil/null or keywords. Collections are not supported yet)  
  Special characters must be first decoded by `decode-url-component`"
  [salt]
  (into {}
        (map
         (fn [[k v]]
           (let [parsed-v (cond
                            (or (= "null" v) (= "nil" v) (= "" v) (nil? v))
                            nil
                            (str/starts-with? v "%3A")
                            (keyword (last (str/split v #"%3A" 2)))
                            :else v)
                 v-spaces (if (some? parsed-v)
                            (str/replace parsed-v #"(%20|\+)" " ")
                            parsed-v)]

             [(keyword k) v-spaces]))
         (map #(str/split % #"=") (str/split salt #"(\&|\?)")))))

(defn decode-base64
  "Cross platform helper function for decoding base64"
  [payload]
  (String. (.decode (Base64/getDecoder) payload)))

(defn encode-base64
  "Base64 encoder. For testing only, so no Cljs."
  [payload]
  (-> (Base64/getEncoder)
      (.encodeToString (.getBytes (str payload) "UTF-8"))))

(defn clj->json
  "Converts a Clojure object to JSON. 
  This is a test helper."
  [input]
  (json/generate-string input))

(defn json->clj
  "Converts a JSON string to a corresponding Clojure object using Cheshire."
  [json-str]
  (json/parse-string json-str true))
