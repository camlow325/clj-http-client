(ns puppetlabs.http.client.sync-ssl-test
  (:import (com.puppetlabs.http.client Sync
                                       HttpClientException
                                       SimpleRequestOptions)
           (javax.net.ssl SSLHandshakeException)
           (java.net URI)
           (org.apache.http ConnectionClosedException)
           (java.security.cert CertificateRevokedException
                               CertPathValidatorException))
  (:require [clojure.test :refer :all]
            [puppetlabs.trapperkeeper.core :as tk]
            [puppetlabs.trapperkeeper.testutils.bootstrap :as testutils]
            [puppetlabs.trapperkeeper.testutils.logging :as testlogging]
            [puppetlabs.trapperkeeper.services.webserver.jetty9-service :as jetty9]
            [puppetlabs.http.client.sync :as sync]
            [schema.test :as schema-test]))

(use-fixtures :once schema-test/validate-schemas)

(defn app
  [req]
  {:status 200
   :body "Hello, World!"})

(tk/defservice test-web-service
  [[:WebserverService add-ring-handler]]
  (init [this context]
        (add-ring-handler app "/hello")
        context))

(deftest sync-client-test-from-pems
  (testlogging/with-test-logging
    (testutils/with-app-with-config app
      [jetty9/jetty9-service test-web-service]
      {:webserver {:ssl-host    "0.0.0.0"
                   :ssl-port    10080
                   :ssl-ca-cert "./dev-resources/ssl/ca.pem"
                   :ssl-cert    "./dev-resources/ssl/cert.pem"
                   :ssl-key     "./dev-resources/ssl/key.pem"}}
      (testing "java sync client"
        (let [request-options (.. (SimpleRequestOptions.
                                    (URI. "https://localhost:10080/hello/"))
                                  (setSslCert "./dev-resources/ssl/cert.pem")
                                  (setSslKey "./dev-resources/ssl/key.pem")
                                  (setSslCaCert "./dev-resources/ssl/ca.pem"))
              response (Sync/get request-options)]
          (is (= 200 (.getStatus response)))
          (is (= "Hello, World!" (slurp (.getBody response))))))
      (testing "clojure sync client"
        (let [response (sync/get "https://localhost:10080/hello/"
                                 {:ssl-cert "./dev-resources/ssl/cert.pem"
                                  :ssl-key "./dev-resources/ssl/key.pem"
                                  :ssl-ca-cert "./dev-resources/ssl/ca.pem"})]
          (is (= 200 (:status response)))
          (is (= "Hello, World!" (slurp (:body response)))))))))

(deftest sync-client-test-from-ca-cert
  (testlogging/with-test-logging
    (testutils/with-app-with-config app
      [jetty9/jetty9-service test-web-service]
      {:webserver {:ssl-host    "0.0.0.0"
                   :ssl-port    10080
                   :ssl-ca-cert "./dev-resources/ssl/ca.pem"
                   :ssl-cert    "./dev-resources/ssl/cert.pem"
                   :ssl-key     "./dev-resources/ssl/key.pem"
                   :client-auth "want"}}
      (testing "java sync client"
        (let [request-options (.. (SimpleRequestOptions.
                                    (URI. "https://localhost:10080/hello/"))
                                  (setSslCaCert "./dev-resources/ssl/ca.pem"))
              response (Sync/get request-options)]
          (is (= 200 (.getStatus response)))
          (is (= "Hello, World!" (slurp (.getBody response))))))
      (testing "clojure sync client"
        (let [response (sync/get "https://localhost:10080/hello/"
                                 {:ssl-ca-cert "./dev-resources/ssl/ca.pem"})]
          (is (= 200 (:status response)))
          (is (= "Hello, World!" (slurp (:body response)))))))))

(deftest sync-client-test-with-invalid-ca-cert
  (testlogging/with-test-logging
    (testutils/with-app-with-config app
      [jetty9/jetty9-service test-web-service]
      {:webserver {:ssl-host    "0.0.0.0"
                   :ssl-port    10081
                   :ssl-ca-cert "./dev-resources/ssl/ca.pem"
                   :ssl-cert    "./dev-resources/ssl/cert.pem"
                   :ssl-key     "./dev-resources/ssl/key.pem"
                   :client-auth "want"}}
      (testing "java sync client"
        (let [request-options (.. (SimpleRequestOptions.
                                    (URI. "https://localhost:10081/hello/"))
                                  (setSslCaCert
                                    "./dev-resources/ssl/alternate-ca.pem"))]
          (try
            (Sync/get request-options)
            ; fail if we don't get an exception
            (is (not true) "expected HttpClientException")
            (catch HttpClientException e
              (is (instance? CertPathValidatorException (-> e
                                                            (.getCause)
                                                            (.getCause)
                                                            (.getCause)
                                                            (.getCause))))))))
      (testing "clojure sync client"
        (try
          (sync/get "https://localhost:10081/hello/"
                    {:ssl-ca-cert "./dev-resources/ssl/alternate-ca.pem"})
          ; fail if we don't get an exception
          (is (not true) "expected SSLHandshakeException")
          (catch SSLHandshakeException e
            (is (instance? CertPathValidatorException (-> e
                                                          (.getCause)
                                                          (.getCause)
                                                          (.getCause))))))))))

(defmacro java-certificate-revoked-exception?
  [& body]
  `(try
     ~@body
     false
     (catch HttpClientException e#
       (instance? CertificateRevokedException (-> e#
                                                  (.getCause)
                                                  (.getCause)
                                                  (.getCause)
                                                  (.getCause)
                                                  (.getCause))))))

(defmacro clj-certificate-revoked-exception?
  [& body]
  `(try
     ~@body
     false
     (catch SSLHandshakeException e#
       (instance? CertificateRevokedException (-> e#
                                                  (.getCause)
                                                  (.getCause)
                                                  (.getCause)
                                                  (.getCause))))))

(defn java-https-get-with-pems-and-crls
  [crls]
  (let [request-options (.. (SimpleRequestOptions.
                              (URI. "https://localhost:10080/hello/"))
                            (setSslCert "./dev-resources/ssl/cert.pem")
                            (setSslKey "./dev-resources/ssl/key.pem")
                            (setSslCaCert "./dev-resources/ssl/ca.pem")
                            (setSslCrls crls))]
    (Sync/get request-options)))

(defn clj-https-get-with-pems-and-crls
  [crls]
  (let [ssl-opts {:ssl-cert    "./dev-resources/ssl/cert.pem"
                  :ssl-key     "./dev-resources/ssl/key.pem"
                  :ssl-ca-cert "./dev-resources/ssl/ca.pem"
                  :ssl-crls    crls}]
    (sync/get "https://localhost:10080/hello/" ssl-opts)))

(deftest sync-client-test-from-pems-and-crls
  (testlogging/with-test-logging
    (testutils/with-app-with-config app
      [jetty9/jetty9-service test-web-service]
      {:webserver {:ssl-host    "0.0.0.0"
                   :ssl-port    10080
                   :ssl-ca-cert "./dev-resources/ssl/ca.pem"
                   :ssl-cert    "./dev-resources/ssl/cert.pem"
                   :ssl-key     "./dev-resources/ssl/key.pem"}}
      (testing "can connect when target not revoked by the crl"
        (testing "java sync client"
          (let [response (java-https-get-with-pems-and-crls
                           "./dev-resources/ssl/crl_none_revoked.pem")]
            (is (= 200 (.getStatus response)))
            (is (= "Hello, World!" (slurp (.getBody response))))))
        (testing "clojure sync client"
          (let [response (clj-https-get-with-pems-and-crls
                           "./dev-resources/ssl/crl_none_revoked.pem")]
            (is (= 200 (:status response)))
            (is (= "Hello, World!" (slurp (:body response)))))))

      (testing "fail with revoked exception when target revoked by the crl"
        (testing "java sync client"
          (is (java-certificate-revoked-exception?
                (java-https-get-with-pems-and-crls
                  "./dev-resources/ssl/crl_localhost_revoked.pem")))))
        (testing "clojure sync client"
          (is (clj-certificate-revoked-exception?
                (clj-https-get-with-pems-and-crls
                  "./dev-resources/ssl/crl_localhost_revoked.pem")))))))

(defn java-https-get-with-ca-cert-and-crls
  [crls]
  (let [request-options (.. (SimpleRequestOptions.
                              (URI. "https://localhost:10080/hello/"))
                            (setSslCaCert "./dev-resources/ssl/ca.pem")
                            (setSslCrls crls))]
    (Sync/get request-options)))

(defn clj-https-get-with-ca-cert-and-crls
  [crls]
  (let [ssl-opts {:ssl-ca-cert "./dev-resources/ssl/ca.pem"
                  :ssl-crls    crls}]
    (sync/get "https://localhost:10080/hello/" ssl-opts)))

(deftest sync-client-test-from-ca-cert-and-crls
  (testlogging/with-test-logging
    (testutils/with-app-with-config app
    [jetty9/jetty9-service test-web-service]
    {:webserver {:ssl-host    "0.0.0.0"
                 :ssl-port    10080
                 :ssl-ca-cert "./dev-resources/ssl/ca.pem"
                 :ssl-cert    "./dev-resources/ssl/cert.pem"
                 :ssl-key     "./dev-resources/ssl/key.pem"
                 :client-auth "want"}}
    (testing "can connect when target not revoked by the crl"
      (testing "java sync client"
        (let [response (java-https-get-with-ca-cert-and-crls
                         "./dev-resources/ssl/crl_none_revoked.pem")]
          (is (= 200 (.getStatus response)))
          (is (= "Hello, World!" (slurp (.getBody response))))))
      (testing "clojure sync client"
        (let [response (clj-https-get-with-ca-cert-and-crls
                         "./dev-resources/ssl/crl_none_revoked.pem")]
          (is (= 200 (:status response)))
          (is (= "Hello, World!" (slurp (:body response)))))))

    (testing "fail with revoked exception when target revoked by the crl"
      (testing "java sync client"
        (is (java-certificate-revoked-exception?
              (java-https-get-with-ca-cert-and-crls
                "./dev-resources/ssl/crl_localhost_revoked.pem")))))
      (testing "clojure sync client"
        (is (clj-certificate-revoked-exception?
              (clj-https-get-with-ca-cert-and-crls
                "./dev-resources/ssl/crl_localhost_revoked.pem")))))))

(defmacro with-server-with-protocols
  [server-protocols server-cipher-suites & body]
  `(testlogging/with-test-logging
    (testutils/with-app-with-config app#
      [jetty9/jetty9-service test-web-service]
      {:webserver (merge
                    {:ssl-host      "0.0.0.0"
                     :ssl-port      10080
                     :ssl-ca-cert   "./dev-resources/ssl/ca.pem"
                     :ssl-cert      "./dev-resources/ssl/cert.pem"
                     :ssl-key       "./dev-resources/ssl/key.pem"
                     :ssl-protocols ~server-protocols}
                    (if ~server-cipher-suites
                      {:cipher-suites ~server-cipher-suites}))}
      ~@body)))

(defmacro java-unsupported-protocol-exception?
  [& body]
  `(try
     ~@body
     false
     (catch HttpClientException e#
       (let [cause# (.getCause e#)]
         (or
           (and (instance? SSLHandshakeException cause#)
                (re-find #"not supported by the client" (.getMessage cause#)))
           (instance? ConnectionClosedException cause#))))))

(defn java-https-get-with-protocols
  [client-protocols client-cipher-suites]
  (let [request-options (.. (SimpleRequestOptions. (URI. "https://localhost:10080/hello/"))
                            (setSslCert "./dev-resources/ssl/cert.pem")
                            (setSslKey "./dev-resources/ssl/key.pem")
                            (setSslCaCert "./dev-resources/ssl/ca.pem"))]
    (if client-protocols
      (.setSslProtocols request-options (into-array String client-protocols)))
    (if client-cipher-suites
      (.setSslCipherSuites request-options (into-array String client-cipher-suites)))
    (Sync/get request-options)))

(defn clj-https-get-with-protocols
  [client-protocols client-cipher-suites]
  (let [ssl-opts (merge {:ssl-cert    "./dev-resources/ssl/cert.pem"
                         :ssl-key     "./dev-resources/ssl/key.pem"
                         :ssl-ca-cert "./dev-resources/ssl/ca.pem"}
                        (if client-protocols
                          {:ssl-protocols client-protocols})
                        (if client-cipher-suites
                          {:cipher-suites client-cipher-suites}))]
    (sync/get "https://localhost:10080/hello/" ssl-opts)))

(deftest sync-client-test-ssl-protocols
  (testing "should be able to connect to a TLSv1.2 server by default"
    (with-server-with-protocols ["TLSv1.2"] nil
      (testing "java sync client"
        (let [response (java-https-get-with-protocols nil nil)]
          (is (= 200 (.getStatus response)))
          (is (= "Hello, World!" (slurp (.getBody response))))))
      (testing "clojure sync client"
        (let [response (clj-https-get-with-protocols nil nil)]
          (is (= 200 (:status response)))
          (is (= "Hello, World!" (slurp (:body response))))))))

  (testing "should be able to connect to a server with non-default protocol if configured"
    (with-server-with-protocols ["SSLv3"] nil
      (testing "java sync client"
        (let [response (java-https-get-with-protocols ["SSLv3"] nil)]
          (is (= 200 (.getStatus response)))
          (is (= "Hello, World!" (slurp (.getBody response))))))
      (testing "clojure sync client"
        (let [response (clj-https-get-with-protocols ["SSLv3"] nil)]
          (is (= 200 (:status response)))
          (is (= "Hello, World!" (slurp (:body response))))))))

  (testing "should not connect to an SSLv3 server by default"
    (with-server-with-protocols ["SSLv3"] nil
      (testing "java sync client"
        (is (java-unsupported-protocol-exception?
              (java-https-get-with-protocols nil nil))))
      (testing "clojure sync client"
        (is (thrown-with-msg?
              SSLHandshakeException #"not supported by the client"
              (clj-https-get-with-protocols nil nil))))))

  (testing "should not connect to a server when protocols don't overlap"
    (with-server-with-protocols ["TLSv1.1"] nil
      (testing "java sync client"
        (is (java-unsupported-protocol-exception?
              (java-https-get-with-protocols ["TLSv1.2"] nil))))
      (testing "clojure sync client"
        (is (thrown-with-msg?
              SSLHandshakeException #"not supported by the client"
              (clj-https-get-with-protocols ["TLSv1.2"] nil)))))))

(deftest sync-client-test-cipher-suites
  (testing "should not connect to a server with no overlapping cipher suites"
    (with-server-with-protocols ["SSLv3"] ["SSL_RSA_WITH_RC4_128_SHA"]
      (testing "java sync client"
        (is (java-unsupported-protocol-exception?
              (java-https-get-with-protocols ["SSLv3"] ["SSL_RSA_WITH_RC4_128_MD5"]))))
      (testing "clojure sync client"
        (is (thrown? ConnectionClosedException
              (clj-https-get-with-protocols ["SSLv3"] ["SSL_RSA_WITH_RC4_128_MD5"]))))))
  (testing "should connect to a server with overlapping cipher suites"
    (with-server-with-protocols ["SSLv3"] ["SSL_RSA_WITH_RC4_128_MD5"]
      (testing "java sync client"
        (let [response (java-https-get-with-protocols ["SSLv3"] ["SSL_RSA_WITH_RC4_128_MD5"])]
          (is (= 200 (.getStatus response)))
          (is (= "Hello, World!" (slurp (.getBody response))))))
      (testing "clojure sync client"
        (let [response (clj-https-get-with-protocols ["SSLv3"] ["SSL_RSA_WITH_RC4_128_MD5"])]
          (is (= 200 (:status response)))
          (is (= "Hello, World!" (slurp (:body response)))))))))