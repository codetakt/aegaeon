macro_rules! impl_team_path {
    ($ty:ty) => {
        impl TeamScopedPath for $ty {
            fn team_id_raw(&self) -> &str {
                &self.team_id
            }
        }
    };
}

macro_rules! impl_team_tenant_path {
    ($ty:ty) => {
        impl_team_path!($ty);
        impl TeamTenantScopedPath for $ty {
            fn tenant_id_raw(&self) -> &str {
                &self.tenant_id
            }
        }
    };
}

macro_rules! impl_team_environment_path {
    ($ty:ty) => {
        impl_team_path!($ty);
        impl TeamEnvironmentScopedPath for $ty {
            fn environment_id_raw(&self) -> &str {
                &self.environment_id
            }
        }
    };
}

macro_rules! impl_team_environment_client_path {
    ($ty:ty) => {
        impl_team_environment_path!($ty);
        impl TeamEnvironmentClientScopedPath for $ty {
            fn client_id_raw(&self) -> &str {
                &self.client_id
            }
        }
    };
}

macro_rules! team_path_struct {
    ($name:ident) => {
        #[derive(Debug, Deserialize)]
        pub(in crate::web::management) struct $name {
            #[serde(rename = "teamId")]
            team_id: String,
        }

        impl_team_path!($name);
    };
}

macro_rules! team_tenant_path_struct {
    ($name:ident) => {
        #[derive(Debug, Deserialize)]
        pub(in crate::web::management) struct $name {
            #[serde(rename = "teamId")]
            team_id: String,
            #[serde(rename = "tenantId")]
            tenant_id: String,
        }

        impl_team_tenant_path!($name);
    };
}

macro_rules! team_environment_path_struct {
    ($name:ident) => {
        #[derive(Debug, Deserialize)]
        pub(in crate::web::management) struct $name {
            #[serde(rename = "teamId")]
            team_id: String,
            #[serde(rename = "environmentId")]
            environment_id: String,
        }

        impl_team_environment_path!($name);
    };
}

macro_rules! team_environment_resource_path_struct {
    ($name:ident, $field:ident, $serde_name:literal) => {
        #[derive(Debug, Deserialize)]
        pub(in crate::web::management) struct $name {
            #[serde(rename = "teamId")]
            team_id: String,
            #[serde(rename = "environmentId")]
            environment_id: String,
            #[serde(rename = $serde_name)]
            $field: String,
        }

        impl_team_environment_path!($name);
    };
}
