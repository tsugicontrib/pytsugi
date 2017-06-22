
import oauth

class TrivialDataStore(object):
    """A database abstraction used to lookup consumers and tokens."""

    secret = False

    def lookup_consumer(self, key):
        print "lookup_consumer",key,secret
        return oauth.OAuthConsumer(key,self.secret)

    def lookup_token(self, oauth_consumer, token_type, token_token):
        return None

    def lookup_nonce(self, oauth_consumer, oauth_token, nonce):
        return False

    def fetch_request_token(self, oauth_consumer):
        return None

    def fetch_access_token(self, oauth_consumer, oauth_token):
        return None

    def authorize_request_token(self, oauth_token, user):
        return True
