(ns altcha-clj.encoding 
  (:require
   [clojure.string :as str]
   #?(:cljs [goog.Uri.QueryData :as query-data])
   ) 
  (:import
   #?(:clj [java.net URLEncoder URLDecoder])))

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
  (if-let [[_ params] (str/split salt #"\?" 2)]
    (into {} 
          (for [param (str/split params #"&")]
            (let [[k v] (str/split param #"=")]
              [(keyword (decode-url-component k))
               (decode-url-component v)])))
    {}))
