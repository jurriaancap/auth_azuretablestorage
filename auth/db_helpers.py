from azure.core.credentials import AzureSasCredential
from azure.core.exceptions import AzureError
from azure.data.tables import TableServiceClient


def connect_to_table(table_name, sas_token, endpoint):
    try:
        credential = AzureSasCredential(sas_token)
        table_service = TableServiceClient(endpoint=endpoint, credential=credential)
        existing_tables = [t.name for t in table_service.list_tables()]
        if table_name not in existing_tables:
            table_service.create_table(table_name)
        return table_service.get_table_client(table_name)
    except AzureError as e:
        raise RuntimeError(f"Azure Table Storage error: {e}")
    except Exception as e:
        raise RuntimeError(
            f"Failed to connect to Azure Table Storage or create table '{table_name}': {e}"
        )
