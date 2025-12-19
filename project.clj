(defproject me.mjholub/altcha-clj "2.0.2"
  :description "A Clojure library designed for working with Altcha challenges."
  :url "https://github.com/mjholub/altcha-clj"
  :license {:name "LGPL-3.0-or-later"
            :url "https://www.gnu.org/licenses/lgpl-3.0.html"}
  :dependencies [[org.clojure/clojure "1.12.0"]
                 [cheshire "6.1.0"]
                 [org.bouncycastle/bcprov-ext-jdk18on "1.78.1"]
                 [pandect "1.0.2"]]
  :repl-options {:init-ns altcha-clj.core})
