from azure.core.credentials import AzureSasCredential
from azure.core.exceptions import AzureError
from azure.data.tables import TableServiceClient, TableEntity


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


def set_entity(table_name, row_key, **fields):
    """
    Create a standardized TableEntity for any table.
    """
    entity = TableEntity(
        PartitionKey=table_name,
        RowKey=row_key,
        **fields
    )
    return entity


def delete_entity(table_client, table_name, row_key):
    try:
        table_client.delete_entity(partition_key=table_name,row_key=row_key)
        return True
    except Exception:
        return False
    


def insert_entity(table_client, table_name, row_key, **fields):
    try:
        entity = set_entity(table_name, row_key, **fields)
        table_client.upsert_entity(entity=entity)
    except AzureError as e:
        raise RuntimeError(f"Azure Table Storage error during insert: {e}")
    except Exception as e:
        raise RuntimeError(f"Failed to insert entity: {e}")


def update_entity(table_client, existing_entity, **new_fields):
    """
    Update an existing entity with new fields.
    """
    try:
        # Update the existing entity with new fields
        for key, value in new_fields.items():
            existing_entity[key] = value
        table_client.upsert_entity(entity=existing_entity)
    except AzureError as e:
        raise RuntimeError(f"Azure Table Storage error during update: {e}")
    except Exception as e:
        raise RuntimeError(f"Failed to update entity: {e}")

def get_entity(table_client, table_name, row_key):
    try:
        return table_client.get_entity(partition_key=table_name, row_key=row_key)
    except AzureError:
        # Entity not found or other Azure error
        return None
    except Exception:
        # Log or handle unexpected errors
        return None

def entity_exists(table_client, table_name, row_key):
    try:
        return get_entity(table_client, table_name, row_key) is not None
    except Exception as e:
        raise RuntimeError(f"Failed to check if entity exists: {e}")
