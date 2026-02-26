from kubernetes import client, config
from kubernetes.client.rest import ApiException


class K8sClient:
    def __init__(self):
        try:
            config.load_kube_config()
        except:
            try:
                config.load_incluster_config()
            except:
                raise Exception("Unable to load kubeconfig")
        
        self.core_v1 = client.CoreV1Api()
        self.apps_v1 = client.AppsV1Api()
        self.rbac_v1 = client.RbacAuthorizationV1Api()
        self.networking_v1 = client.NetworkingV1Api()
        self.batch_v1 = client.BatchV1Api()
    
    def get_all_pods(self):
        try:
            return self.core_v1.list_pod_for_all_namespaces(watch=False).items
        except ApiException as e:
            return []
    
    def get_all_secrets(self):
        try:
            return self.core_v1.list_secret_for_all_namespaces(watch=False).items
        except ApiException as e:
            return []
    
    def get_all_configmaps(self):
        try:
            return self.core_v1.list_config_map_for_all_namespaces(watch=False).items
        except ApiException as e:
            return []
    
    def get_all_services(self):
        try:
            return self.core_v1.list_service_for_all_namespaces(watch=False).items
        except ApiException as e:
            return []
    
    def get_all_deployments(self):
        try:
            return self.apps_v1.list_deployment_for_all_namespaces(watch=False).items
        except ApiException as e:
            return []
    
    def get_all_statefulsets(self):
        try:
            return self.apps_v1.list_stateful_set_for_all_namespaces(watch=False).items
        except ApiException as e:
            return []
    
    def get_all_daemonsets(self):
        try:
            return self.apps_v1.list_daemon_set_for_all_namespaces(watch=False).items
        except ApiException as e:
            return []
    
    def get_all_roles(self):
        try:
            return self.rbac_v1.list_role_for_all_namespaces(watch=False).items
        except ApiException as e:
            return []
    
    def get_all_cluster_roles(self):
        try:
            return self.rbac_v1.list_cluster_role(watch=False).items
        except ApiException as e:
            return []
    
    def get_all_role_bindings(self):
        try:
            return self.rbac_v1.list_role_binding_for_all_namespaces(watch=False).items
        except ApiException as e:
            return []
    
    def get_all_cluster_role_bindings(self):
        try:
            return self.rbac_v1.list_cluster_role_binding(watch=False).items
        except ApiException as e:
            return []
    
    def get_all_network_policies(self):
        try:
            return self.networking_v1.list_network_policy_for_all_namespaces(watch=False).items
        except ApiException as e:
            return []
    
    def get_all_namespaces(self):
        try:
            return self.core_v1.list_namespace(watch=False).items
        except ApiException as e:
            return []
    
    def get_all_cronjobs(self):
        try:
            return self.batch_v1.list_cron_job_for_all_namespaces(watch=False).items
        except ApiException as e:
            return []
    
    def get_all_jobs(self):
        try:
            return self.batch_v1.list_job_for_all_namespaces(watch=False).items
        except ApiException as e:
            return []
    
    def get_all_ingresses(self):
        try:
            return self.networking_v1.list_ingress_for_all_namespaces(watch=False).items
        except ApiException as e:
            return []
