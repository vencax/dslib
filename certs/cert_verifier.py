import cert_finder

#*    dslib - Python library for Datove schranky
#*    Copyright (C) 2009-2012  CZ.NIC, z.s.p.o. (http://www.nic.cz)
#*
#*    This library is free software; you can redistribute it and/or
#*    modify it under the terms of the GNU Library General Public
#*    License as published by the Free Software Foundation; either
#*    version 2 of the License, or (at your option) any later version.
#*
#*    This library is distributed in the hope that it will be useful,
#*    but WITHOUT ANY WARRANTY; without even the implied warranty of
#*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#*    Library General Public License for more details.
#*
#*    You should have received a copy of the GNU Library General Public
#*    License along with this library; if not, write to the Free
#*    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#*
'''
Module for certificate verification.
'''

# standard library imports
import logging
import types

# dslib imports
from pyasn1.codec.der import encoder
from pyasn1 import error
from dslib.pkcs7.asn1_models.oid import *
from dslib.pkcs7.digest import *
from dslib.pkcs7 import verifier
from dslib.pkcs7 import rsa_verifier

# local imports
import crl_store
from cert_finder import *
import timeutil
from constants import *

logger = logging.getLogger("certs.cert_verifier")

def _verify_date(certificate):
    '''
    Checks date boundaries in the certificate (actual time must be inside).
    '''
    tbs = cert_finder._get_tbs_certificate(certificate)
    validity = tbs.getComponentByName("validity")
    start = validity.getComponentByName("notBefore").getComponentByPosition(0)._value

    start_time = timeutil.to_time(start)#time.strptime(start, format)
    end = validity.getComponentByName("notAfter").getComponentByPosition(0)._value
    end_time = timeutil.to_time(end)#time.strptime(end, format)
    now = timeutil.now()#time.gmtime()

    if (start_time < now) and (end_time > now):
        return True
    logger.warning("Out of boundaries of validity:  %s - %s." %\
                (start, end))
    return False

def _check_crl(checked_cert, issuer_cert, force_download=False):
    '''
    Checks if the certificate is not revoked by its issuer.
    '''
    # extract CDT from issuer certificate
    # find issuer and its cdt in cache
    # add them eventually to cache
    # check the issuer and sn of checked cert if they are in the cache
    # if yes, return False

    tbs = cert_finder._get_tbs_certificate(checked_cert)
    # serial number of checked certificate
    cert_sn = tbs.getComponentByName("serialNumber")._value
    # get the CRL cache
    crl_cache = crl_store.CRL_cache_manager.get_cache()
    # get the name of issuer of CRL
    issuer_name = str(tbs.getComponentByName("issuer"))
    from pkcs7_models import X509Certificate
    # extract CDPs from checked certificate
    c = X509Certificate(checked_cert)
    dist_points = crl_store.extract_crl_distpoints(c)
    # look for CRL issuer in the cache
    iss = crl_cache.get_issuer(issuer_name)
    download_crl_success = False
    if iss is None:
      # add new CRL issuer
      added = crl_cache.add_issuer(issuer_name)
      # add issuer's CDPs to issuer
      for dp in dist_points:
        added_dp = added.add_dist_point(dp)
        if added_dp is not None:
          crl_cache.changed = True
          # initialize added CDP
          download_success, added_certs = added.init_dist_point(dp, verification=issuer_cert)
          # if download of CRL was successful, ignore other CDP
          if download_success:
            download_crl_success = True
            break
    else:
      # if CRL issuer exists, only refresh his CDPs
      download_crl_success, added_certs = iss.\
                                      refresh_issuer(verification=issuer_cert, \
                                                     force_crl_download=force_download)
      if iss.changed:
        crl_cache.change = True

    # if CRL download failed from each CDP and the cache
    # is empty, return False - we cannot say anything about
    # certificate revoked status
    if not download_crl_success:
      logger.warning("Cannot download CRL from any CDP!")
      if (len(crl_cache.issuers) == 0):
        logger.error("CRL cache empty, cannot say anything about certificate revoked status")
        logger.error("Certificate check against CRL failed, download of CRLs failed")
        return False
      logger.warning("Using locally stored CRLs")
    # check the CRL cache for the certificate issuer and serial number
    is_revoked = crl_cache.is_certificate_revoked(issuer_name, cert_sn)
    # if it is not revoked, checked certificate is ok
    if is_revoked is False:
      return True
    else:
      rev_date = crl_cache.certificate_rev_date(issuer_name, cert_sn)
      logger.warning("Certificate %s revoked on %s" % (cert_sn, rev_date))
      return False



def verify_certificate(cert, trusted_ca_certs=[],\
                       check_crl=False, force_crl_download=False):
    '''
    Verifies the certificate - checks signature and date validity.
    '''
    results = {"TRUSTED_CERTS_EXIST": None,
               "SIGNING_ALG_OK" : None,
               "TRUSTED_PARENT_FOUND":None,
               "CERT_TIME_VALIDITY_OK": None,
               "CERT_NOT_REVOKED": None,
               "CERT_SIGNATURE_OK": None
    }

    if len(trusted_ca_certs) == 0:
        logger.error("No trusted certificate found")
        results["TRUSTED_CERTS_EXIST"] = False
    else:
        results["TRUSTED_CERTS_EXIST"] = True
    # extract tbs certificate
    tbs = cert_finder._get_tbs_certificate(cert)
    # encode tbs into der
    tbs_encoded = encoder.encode(tbs)
    # hash tbs with used digest algorithm
    sig_alg = str(cert.getComponentByName("signatureAlgorithm"))
    sa_name = oid_map[sig_alg]

    if (sa_name == SHA1RSA_NAME):
        calculated_digest = calculate_digest(tbs_encoded, SHA1_NAME)
        results["SIGNING_ALG_OK"] = True
    elif (sa_name == SHA256RSA_NAME):
        calculated_digest = calculate_digest(tbs_encoded, SHA256_NAME)
        results["SIGNING_ALG_OK"] = True
    else:
        msg = "Unknown certificate signature algorithm: %s" % sig_alg
        logger.error(msg)
        results["SIGNING_ALG_OK"] = False
        # we dont have to continue, if we do not know signing algorithm
        return results

    # look for signing certificate among certificates
    issuer = str(tbs.getComponentByName("issuer"))
    subject = str(tbs.getComponentByName("subject"))
    signing_cert = find_cert_by_subject(issuer, trusted_ca_certs)
    if not signing_cert:
        msg = "No certificate found for %s, needed to verify certificate of %s" %\
               (issuer,subject)
        logger.error(msg)
        results["TRUSTED_PARENT_FOUND"] = False
        # we do not have to continue - there is no signing certificate,
        # therefore we have no key to verify this certificate
        return results
    else:
        results["TRUSTED_PARENT_FOUND"] = True

    # check validity of certificate - validity period etc.
    if not _verify_date(cert):
        msg = "Certificate out of validity period"
        logger.error(msg)
        #return False
        results["CERT_TIME_VALIDITY_OK"] = False
    else:
        results["CERT_TIME_VALIDITY_OK"] = True

    # if we want to download and check the crl of issuing authority
    # for certificate being checked
    if check_crl:
        is_ok = _check_crl(cert, signing_cert, force_download=force_crl_download)
        csn = tbs.getComponentByName("serialNumber")._value
        if not is_ok:
          msg = "Certificate %d issued by %s is revoked" % (csn,issuer)
          logger.error(msg)
          results["CERT_NOT_REVOKED"] = False
        else:
          logger.info("Certificate %d of %s is not on CRL" % (csn,issuer))
          results["CERT_NOT_REVOKED"] = True

    # extract public key from matching certificate
    alg, key_material = verifier._get_key_material(signing_cert)
    # decrypt signature in explored certificate
    signature = cert.getComponentByName("signatureValue").toOctets()
    # compare calculated hash and decrypted signature
    res = rsa_verifier.rsa_verify(calculated_digest, signature, key_material)

    results["CERT_SIGNATURE_OK"] = res

    return results
