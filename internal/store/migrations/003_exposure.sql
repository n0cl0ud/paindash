-- internet | internal | none, from the IngressRoutes and LoadBalancer Services
-- routing to the workload's pods.
ALTER TABLE containers ADD COLUMN exposure text NOT NULL DEFAULT 'none';
