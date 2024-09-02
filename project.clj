(defproject me.mjholub/altcha-clj "1.4.0"
  :description "A Clojure/script library designed for working with Altcha challenges."
  :url "https://github.com/mjholub/altcha-clj"
  :license {:name "LGPL-3.0-or-later"
            :url "https://www.gnu.org/licenses/lgpl-3.0.html"}
  :dependencies [[org.clojure/clojure "1.11.2"]
                 [cheshire "5.13.0"]
                 [org.bouncycastle/bcprov-ext-jdk18on "1.78.1"]
                 [pandect "1.0.2"]
                 ]
  :repl-options {:init-ns altcha-clj.core})
