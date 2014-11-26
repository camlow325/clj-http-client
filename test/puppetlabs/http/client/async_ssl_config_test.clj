(ns puppetlabs.http.client.async-ssl-config-test
  (:require [clojure.test :refer :all]
            [clojure.java.io :refer [resource]] 
            [puppetlabs.certificate-authority.core :as ssl]
            [puppetlabs.http.client.async :as http]
            [schema.test :as schema-test])
  (:import [javax.net.ssl SSLContext]))

(use-fixtures :once schema-test/validate-schemas)

(deftest ssl-config-with-cert-key-and-ca-files
  (let [opts {:ssl-cert    (resource "ssl/cert.pem")
              :ssl-key     (resource "ssl/key.pem")
              :ssl-ca-cert (resource "ssl/ca.pem")}
        configured-opts (http/configure-ssl-ctxt opts)]

    (testing "configure-ssl-ctxt sets up an SSLContext when given cert, key, ca-cert"
      (is (instance? SSLContext (:ssl-context configured-opts))))

    (testing "removes ssl-cert, ssl-key, ssl-ca-cert"
      (is (not (:ssl-cert configured-opts)))
      (is (not (:ssl-key configured-opts)))
      (is (not (:ssl-ca-cert configured-opts))))))

(deftest ssl-config-with-cert-key-ca-and-crls-files
  (let [opts {:ssl-cert    (resource "ssl/cert.pem")
              :ssl-key     (resource "ssl/key.pem")
              :ssl-ca-cert (resource "ssl/ca.pem")
              :ssl-crls    (resource "ssl/crl_none_revoked.pem")}
        configured-opts (http/configure-ssl-ctxt opts)]

    (testing (str "configure-ssl-ctxt sets up an SSLContext when given cert, "
                  "key, ca-cert, and crls"
      (is (instance? SSLContext (:ssl-context configured-opts))))

    (testing "removes ssl-cert, ssl-key, ssl-ca-cert, ssl-crls"
      (is (not (:ssl-cert configured-opts)))
      (is (not (:ssl-key configured-opts)))
      (is (not (:ssl-ca-cert configured-opts)))
      (is (not (:ssl-crls configured-opts)))))))

(deftest ssl-config-with-ca-file
  (let [opts {:ssl-ca-cert (resource "ssl/ca.pem")}
        configured-opts (http/configure-ssl-ctxt opts)]

    (testing "configure-ssl-ctxt sets up an SSLContext when given ca-cert"
      (is (instance? SSLContext (:ssl-context configured-opts))))

    (testing "removes ssl-ca-cert"
      (is (not (:ssl-ca-cert configured-opts))))))

(deftest ssl-config-with-ca-and-crls-files
  (let [opts {:ssl-ca-cert (resource "ssl/ca.pem")
              :ssl-crls    (resource "ssl/crl_none_revoked.pem")}
        configured-opts (http/configure-ssl-ctxt opts)]

    (testing "configure-ssl-ctxt sets up an SSLContext when given ca-cert"
      (is (instance? SSLContext (:ssl-context configured-opts))))

    (testing "removes ssl-ca-cert and ssl-crls"
      (is (not (:ssl-ca-cert configured-opts)))
      (is (not (:ssl-crls configured-opts))))))

(deftest ssl-config-without-ssl-params
  (let [configured-opts (http/configure-ssl-ctxt {})]

    (testing "configure-ssl-ctxt does nothing when given no ssl parameters"
      (is (= {} configured-opts)))))

(deftest ssl-config-with-context
  (let [opts {:ssl-context (ssl/pems->ssl-context
                            (resource "ssl/cert.pem")
                            (resource "ssl/key.pem")
                            (resource "ssl/ca.pem"))}
        configured-opts (http/configure-ssl-ctxt opts)]

    (testing "configure-ssl-ctxt uses an existing ssl context"
      (is (instance? SSLContext (:ssl-context configured-opts))))))