# encoding: utf-8
"""
This modules hosts classes that reflect objects used in the
DS SOAP interface.
The purpose of these classes is to provide further functionality,
such as serialization, etc.
"""

import logging
import os
import constants

from pkcs7_models import *

class Model(object):

  KNOWN_ATTRS = ()
  ATTR_TO_TYPE = {}

  def __init__(self, soap_message=None, xml_document=None):
    self._init_default()    
    if soap_message:
      self._load_from_soap(soap_message)
    if xml_document is not None:
      self._load_from_xml_document(xml_document)


  def __unicode__(self):
    ret = u"%s:" % self.__class__.__name__
    for a in self.__class__.KNOWN_ATTRS:
      ret += u"\n  %s: %s" % (a, unicode(getattr(self, a)))
    return ret

  def __str__(self):
    return unicode(self).encode('utf-8')

  # ---------- private methods ----------

  def _init_default(self):
    for attr in self.__class__.KNOWN_ATTRS:
      if attr in self.__class__.ATTR_TO_TYPE:
        value = self.__class__.ATTR_TO_TYPE[attr]()
      else:
        value = None
      setattr(self, attr, value)
  


  def _load_from_soap(self, soap):
    _origin = soap.__class__.__name__
    for a in self.__class__.KNOWN_ATTRS:
      parent = soap
      self._load_one_attr(parent, a)

  
  def _load_one_attr(self, parent, attr):
    if hasattr(parent, attr):
      value = getattr(parent, attr)
      # some hardcoded stuff
      typ = value.__class__.__name__
      if typ == "tEventsArray":
        if type(value.dmEvent) == list:
          todo = value.dmEvent
        else:
          todo = [value.dmEvent]
        values = [dmEvent(child) for child in todo]
        setattr(self, attr, values)
      elif typ == "tFilesArray":
        values = [dmFile(child) for child in value.dmFile]
        setattr(self, attr, values)
      elif typ == "dmHash":
        setattr(self, attr, dmHash(value))
      else:
        setattr(self, attr, self._decode_soap_value(value))
    else:
      logging.debug("Attribute %s not present in %s", attr, parent.__class__.__name__)
    

  def _decode_soap_value(self, soap):
    """take a value as returned by SOAP and return a more suitable one;
    for example suds uses a class for text, so we translate to normal
    unicode string here"""
    if soap.__class__.__name__ == "Text":
      return unicode(soap)
    return soap


  def copy_to_soap_object(self, soap):
    for attr in self.KNOWN_ATTRS:
      value = getattr(self, attr)
      if value != None:
        # we do not copy default empty values
        self._set_one_attr(soap, attr, value)


  def _set_one_attr(self, soap, attr, value):
##     if attr == "dmFiles":
##       for child in value:
##         soap_child = dmFile()
##         child.copy_to_soap_object(soap_child)
    setattr(soap, attr, value)
  
  '''
  Returns value of xml attribute
  '''
  def _get_attribute_value(self, xml_attribute):
      return xml_attribute.getValue()
  
  '''
  Returns text value of child node 
  '''
  def _get_child_text_value(self, xml_child):
      return xml_child.text
  
  
  def _load_one_xml_att(self, parent, attr):
      
      if attr[0] == '_':
          entity = parent.attrib(attr[1:])
      else:
          entity = parent.getChild(attr)
          
      if entity is not None:
          if attr[0] == '_':
              value = self._get_attribute_value(entity)
          else:
              value = self._get_child_text_value(entity)
          
          if (attr == "dmFiles"):
              files = entity.getChildren()
              values = [dmFile(xml_document=file) for file in files]
              for file in files:
                  s = dmFile(xml_document=file)
              setattr(self, attr, values)
          elif (attr == "dmEvents"):
              events = entity.getChildren()
              values = [dmEvent(xml_document=event) for event in events]
              setattr(self, attr, values)
          elif (attr == "dmHash"):
              x = dmHash(xml_document=entity)
              setattr(self, attr, dmHash(xml_document=entity))              
          else:
              setattr(self, attr, value)          
      else:
          logging.debug("Attribute %s not present in %s", attr, parent.text)
    
    
  def _load_from_xml_document(self, xml_doc, root_name=None):      
      for a in self.__class__.KNOWN_ATTRS:
          parent = xml_doc
          self._load_one_xml_att(parent, a)
          

class Message(Model):
  """reflection of the DS message, which could be a result from
  several SOAP calles, namely: MessageDownload, MessageEnvelopeDownload,
  GetListOfSentMessages and GetListOfReceivedMessages"""

  KNOWN_ATTRS = ("dmID", "dbIDSender", "dmSender", "dmSenderAddress",
                 "dmSenderType", "dmRecipient", "dmRecipientAddress",
                 "dmAmbiguousRecipient", "dmSenderOrgUnit", "dmSenderOrgUnitNum",
                 "dbIDRecipient", "dmRecipientOrgUnit", "dmRecipientOrgUnitNum",
                 "dmToHands", "dmAnnotation", "dmRecipientRefNumber",
                 "dmSenderRefNumber", "dmRecipientIdent", "dmSenderIdent",
                 "dmLegalTitleLaw", "dmLegalTitleYear", "dmLegalTitleSect",
                 "dmLegalTitlePar", "dmLegalTitlePoint", "dmPersonalDelivery",\
                 "dmAllowSubstDelivery", "dmFiles",
                 "dmHash", "dmQTimestamp", "dmDeliveryTime", "dmAcceptanceTime",
                 "dmMessageStatus", "dmAttachmentSize", "dmEvents")

  ATTR_TO_TYPE = {"dmFiles":list, "dmEvents":list}

  # attributes of message returned outside in case of MessageEnvelopeDownload,
  # MessageDownload, GetDeliveryInfo
  OUTSIDE_ATTRS = ("dmDeliveryTime","dmAcceptanceTime","dmMessageStatus",
                   "dmAttachmentSize","dmHash","dmQTimestamp","dmEvents")

  # origins in which some info (described above in OUTSIDE_ATTRS) is placed outside
  SPLIT_ORIGINS = ("tReturnedMessageEnvelope","tReturnedMessage","tDelivery")
  
  SIG_DELIVERY_CONTENT_PATH = "GetDeliveryInfoResponse/dmDelivery"
  
  SIG_MESSAGE_CONTENT_PATH =  "MessageDownloadResponse/dmReturnedMessage" 
  
  # has meaning only if msg contains pkcs7_data
  is_verified = False
  # all PKCS7 data are stored in pkcs7_data attribute
  pkcs7_data = None
    
  def __init__(self, soap_message=None, xml_document=None, path_to_content=None):
    if (xml_document is not None) and (path_to_content is None):
        raise Exception("Must specify path to the content of message!")
    self.content_path = path_to_content    
    Model.__init__(self, soap_message, xml_document)
    # ---------- public methods ----------

  def get_origin(self):
    """returns a string describing from which SOAP call this Message comes;
    this could be used to determine which parts are (or should be) present."""
    return self._origin

  def get_status_description(self):
    return constants.MESSAGE_STATUS.get(self.dmMessageStatus, u"neznámy")
  
  def has_PKCS7_data(self):
      if self.pkcs7_data:
          return True
      else:
          return False


  # ---------- private methods ----------

  # overrides the Model._load_from_soap
  def _load_from_soap(self, soap):
    _origin = soap.__class__.__name__
    for a in Message.KNOWN_ATTRS:
      if a in Message.OUTSIDE_ATTRS or _origin not in Message.SPLIT_ORIGINS:
        # get if directly
        parent = soap
      else:
        parent = soap.dmDm
      self._load_one_attr(parent, a)
    self._origin = _origin
    
  def _load_from_xml_document(self, xml_doc):
    # split path to content by /
    parts = self.content_path.split('/')
    root = xml_doc
    # go down the xml tree to reach the start of "message envelope"
    for part in parts:
        root = root.getChild(part)
        if root is None:
            raise Exception("Could not reach the message content node, check specified path to the content")

    for a in Message.KNOWN_ATTRS:
        if a in Message.OUTSIDE_ATTRS: 
            parent = root
        else:
            parent = root.getChild("dmDm")
        self._load_one_xml_att(parent, a)


class dmFile(Model):
  """this class corresponds to the SOAP dmFile class"""

  KNOWN_ATTRS = ("_dmFileDescr","_dmUpFileGuid","_dmFileGuid","_dmMimeType","_dmFormat",
                 "_dmFileMetaType","dmEncodedContent")

  import os
  import base64

  def get_decoded_content(self):
    import base64
    return base64.standard_b64decode(self.dmEncodedContent)

  def get_size(self):
    """just approximate it"""
    return int(6.0 * len(self.dmEncodedContent) / 8)

  def save_file(self, dir, fname=None):
    """if fname is null, the one in the file_obj will be used"""
    if not fname:
      fname = self._dmFileDescr
    fullname = os.path.join(dir, fname)
    outf = file(fullname, "wb")
    outf.write(self.get_decoded_content())
    outf.close()
    return fullname
    
class dmFiles(Model):

  KNOWN_ATTRS = ("dmFile",)
  ATTR_TO_TYPE = {"dmFile":list}
          

class dmEvent(Model):
  """corresponds to dmEvent SOAP class"""

  KNOWN_ATTRS = ("dmEventTime", "dmEventDescr")



class dmStatus(Model):
  """corresponds to dmStatus SOAP class"""

  KNOWN_ATTRS = ("dmStatusCode", "dmStatusMessage")


class dbStatus(Model):
  """corresponds to dmStatus SOAP class"""

  KNOWN_ATTRS = ("dbStatusCode", "dbStatusMessage")


class dmHash(Model):
  """corresponds to dmHash SOAP class"""

  KNOWN_ATTRS = ("value", "_algorithm")

  '''
  Override Model _load>from_xml_document
  '''
  def _load_from_xml_document(self, xml_doc):
      self.value = xml_doc.text
      self._load_one_xml_att(xml_doc, "_algorithm")

class dmEnvelope(Model):

  KNOWN_ATTRS = ("dmSenderOrgUnit", "dmSenderOrgUnitNum", "dbIDRecipient", "dmRecipientOrgUnit",
                 "dmRecipientOrgUnitNum", "dmToHands", "dmAnnotation", "dmRecipientRefNumber",
                 "dmSenderRefNumber", "dmRecipientIdent", "dmSenderIdent", "dmLegalTitleLaw",
                 "dmLegalTitleYear", "dmLegalTitleSect", "dmLegalTitlePar", "dmLegalTitlePoint",
                 "dmPersonalDelivery", "dmAllowSubstDelivery", "dmOVM")
  
  
class dbOwnerInfo(Model):

  KNOWN_ATTRS = ("dbID", "dbType", "ic", "pnFirstName", "pnMiddleName", "pnLastName",
                 "pnLastNameAtBirth", "firmName", "biDate", "biCity", "biCounty",
                 "biState", "adCity", "adStreet", "adNumberInStreet", "adNumberInMunicipality",
                 "adZipCode", "adState", "nationality", "identifier", "registryCode",
                 "dbState", "dbEffectiveOVM", "dbOpenAddressing")