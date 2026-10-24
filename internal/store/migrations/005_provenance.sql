-- Where an image was built from, from the OCI labels its SBOM recorded
-- (org.opencontainers.image.source / .revision). NULL until read, '' if absent.
ALTER TABLE images ADD COLUMN source text, ADD COLUMN revision text;
