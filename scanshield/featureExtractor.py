import whois
from urllib.parse import urlparse
import httpx
import pickle as pk
import pandas as pd
import extractorFunctions as ef

#Function to extract features
def featureExtraction(url):

  features = []
  # Caractéristiques Basées sur l’URL (6 features)
  features.append(ef.getLength(url))
  features.append(ef.getDepth(url))
  features.append(ef.tinyURL(url))
  features.append(ef.prefixSuffix(url))
  features.append(ef.no_of_dots(url))
  features.append(ef.sensitive_word(url))


  domain_name = ''
  #Caractéristiques Basées sur le Domaine (WHOIS)(2 features)
  dns = 0
  try:
    domain_name = whois.whois(urlparse(url).netloc)  # Interroge WHOIS
  except:
    dns = 1   # Marque un échec de requête WHOIS

  features.append(1 if dns == 1 else ef.domainAge(domain_name))  # Âge du domaine
  features.append(1 if dns == 1 else ef.domainEnd(domain_name))  # Date d'expiration

  # Caractéristiques HTML/JavaScript (4 features)
  dom = []
  try:
    response = httpx.get(url)   # Requête HTTP
  except:
    response = ""               # Échec → réponse vide

  dom.append(ef.iframe(response))     # Détection d'iframes
  dom.append(ef.mouseOver(response))  # Événements "mouseOver"
  dom.append(ef.forwarding(response)) # Redirections suspectes

  features.append(ef.has_unicode(url)+ef.haveAtSign(url)+ef.havingIP(url))

  with open('model/pca_model.pkl', 'rb') as file:
    pca = pk.load(file)

  #converting the list to dataframe
  feature_names = ['URL_Length', 'URL_Depth', 'TinyURL', 'Prefix/Suffix', 'No_Of_Dots', 'Sensitive_Words',
                       'Domain_Age', 'Domain_End', 'Have_Symbol','domain_att']
  dom_pd = pd.DataFrame([dom], columns = ['iFrame','Web_Forwards','Mouse_Over'])
  features.append(pca.transform(dom_pd)[0][0])   # Applique PCA

  row = pd.DataFrame([features], columns= feature_names)

  return row