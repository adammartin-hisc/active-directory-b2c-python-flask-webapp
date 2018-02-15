from azure.graphrbac import GraphRbacManagementClient
from azure.common.credentials import ServicePrincipalCredentials
import string, json

def get_user(email, config):
    filterTemplate=string.Template("otherMails/any(c:c eq '$email')")
    filter = filterTemplate.substitute(email=email)
    user = next(_client(config).users.list(filter=filter), None)
    if user:
        user.enable_additional_properties_sending()
    return json.dumps(user.serialize(), indent=4, sort_keys=True)

def _client(config):
	return GraphRbacManagementClient(_credentials(config), config['tenant_id'])

def _credentials(config):
	return ServicePrincipalCredentials(
        client_id=config['graph_client_id'],
        secret=config['graph_client_secret'],
        tenant=config['tenant_id'],
        resource=config['ad_graph_url'])
