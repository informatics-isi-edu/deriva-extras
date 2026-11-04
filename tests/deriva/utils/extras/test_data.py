import pytest
import urllib.parse
import requests
from unittest.mock import MagicMock, patch

# Import your functions from the utils.data module
from deriva.utils.extras.data import (
    approx_json_bytecnt,
    update_table_rows,
    get_key_values,
    get_batch_size_by_str_length,
    delete_table_rows,
    delete_table_rows_by_keys
)


# ==============================================================================
# Pytest Unit Tests
# ==============================================================================

class TestApproxJsonBytecnt:
    """Test suite for the approx_json_bytecnt utility function."""

    def test_primitives(self):
        # None -> 'null' (4 bytes)
        assert approx_json_bytecnt(None) == 4
        # Booleans -> 'true' (4), 'false' (5)
        assert approx_json_bytecnt(True) == 4
        assert approx_json_bytecnt(False) == 5
        # Numbers -> '123' (3), '3.14' (4)
        assert approx_json_bytecnt(123) == 3
        assert approx_json_bytecnt(3.14) == 4

    def test_strings(self):
        # "hello" -> '"hello"' (7 bytes)
        assert approx_json_bytecnt("hello") == 7
        
        # UTF-8 characters: "ñ" is 2 bytes + 2 quotes = 4 bytes
        assert approx_json_bytecnt("ñ") == 4
        
        # Emoji: "🚀" is 4 bytes + 2 quotes = 6 bytes
        assert approx_json_bytecnt("🚀") == 6

    def test_string_escapes(self):
        # String with newline: "a\nb" -> '"a\nb"' (JSON needs \\n, so +1 byte)
        # 2 quotes + 3 raw chars + 1 escape char = 6
        assert approx_json_bytecnt("a\nb") == 6
        
        # String with backslash: "a\b" -> '"a\\b"'
        assert approx_json_bytecnt("a\\b") == 6
        
        # String with quotes: 'a"b' -> '"a\"b"'
        assert approx_json_bytecnt('a"b') == 6

    def test_collections(self):
        # list: [1] -> '[' + '1' + ',' + ']' = 4 bytes
        # Note: The actual JSON "[1]" is 3 bytes. The function overestimates 
        # by 1 for the trailing comma logic, which is expected/acceptable for approx bounds.
        assert approx_json_bytecnt([1]) == 4
        
        # dict: {"a": 1} -> '{' + '"a"' + ':' + '1' + ',' + '}' = 2+3+1+1+1 = 8 bytes
        # Actual JSON '{"a":1}' is 7 bytes (overestimated by 1 for trailing comma).
        assert approx_json_bytecnt({"a": 1}) == 8

    def test_nested_collections(self):
        # Nested structures should recurse properly
        data = {"keys": [1, 2, 3]}
        # Dict overhead: 2
        # Key "keys": 2 quotes + 4 chars = 6
        # Dict syntax (colon + comma): 2
        # List overhead: 2
        # List elements: (1+1) + (1+1) + (1+1) = 6
        # Total: 2 + 6 + 2 + 2 + 6 = 18 bytes
        assert approx_json_bytecnt(data) == 18

    def test_invalid_type(self):
        # Sets are not natively JSON serializable
        with pytest.raises(TypeError, match="cannot estimate size of unexpected data"):
            approx_json_bytecnt({1, 2, 3})


class TestUpdateTableRows:
    """Test suite for the update_table_rows utility function."""

    @pytest.fixture
    def mock_catalog(self):
        catalog = MagicMock()
        
        # Mock ERMrest model structure for column auto-discovery
        mock_table = MagicMock()
        mock_table.columns.elements = ["RID", "col1", "col2", "RCT"]
        
        mock_schema = MagicMock()
        mock_schema.tables = {"test_table": mock_table}
        
        mock_model = MagicMock()
        mock_model.schemas = {"test_schema": mock_schema}
        
        catalog.getCatalogModel.return_value = mock_model
        
        # Mock catalog.put response
        mock_resp = MagicMock()
        mock_resp.json.return_value = [{"RID": "123", "col1": "A"}]
        catalog.put.return_value = mock_resp
        
        return catalog

    def test_empty_payload(self, mock_catalog):
        # Should return early with an empty list without contacting catalog
        assert update_table_rows(mock_catalog, "s", "t", payload=[]) == []
        mock_catalog.put.assert_not_called()

    def test_column_auto_discovery(self, mock_catalog):
        payload = [{"RID": "123", "col1": "A", "col2": "B"}]
        
        with patch("deriva.utils.extras.data.approx_json_bytecnt", return_value=10):
            result = update_table_rows(mock_catalog, "test_schema", "test_table", payload=payload)
            
            mock_catalog.put.assert_called_once()
            url_called = mock_catalog.put.call_args[0][0]
            
            # Verify system columns (RID, RCT) are excluded and valid columns are formatted
            assert "/attributegroup/test_schema:test_table/RID;col1,col2" in url_called
            assert result == [{"RID": "123", "col1": "A"}]

    def test_empty_column_names_warning(self, mock_catalog):
        # Table only contains system columns, leaving auto-discovered columns empty
        mock_catalog.getCatalogModel().schemas["test_schema"].tables["test_table"].columns.elements = ["RID", "RCT"]
        payload = [{"RID": "123"}]
        
        with patch("deriva.utils.extras.data.logger") as mock_logger:
            result = update_table_rows(mock_catalog, "test_schema", "test_table", payload=payload)
            
            assert result == []
            mock_logger.warning.assert_called_once_with("WARNING: column names to be updated is empty")
            mock_catalog.put.assert_not_called()

    def test_linear_backoff_algorithm(self, mock_catalog):
        # 2500 total rows payload
        payload = [{"RID": str(i), "col1": "val"} for i in range(2500)]
        
        # Mock byte counter: returns 2000 bytes per row
        def fake_bytecnt(data):
            return len(data) * 2000
            
        with patch("deriva.utils.extras.data.approx_json_bytecnt", side_effect=fake_bytecnt):
            # batch_bytes limit is 1,000,000 bytes (fits max 500 rows)
            # Initial batch_size = 2500 (5,000,000 bytes -> exceeds limit)
            # 1st step: nrows = max(1, 2500 - 1000) = 1500 (3,000,000 bytes -> exceeds limit)
            # 2nd step: nrows = max(1, 1500 - 1000) = 500 (1,000,000 bytes -> fits limit!)
            update_table_rows(
                mock_catalog, "test_schema", "test_table", 
                keys=["RID"], column_names=["col1"], 
                payload=payload, 
                batch_size=2500, 
                batch_bytes=1000000
            )
            
            # 2500 items split into batches of 500 = 5 calls to catalog.put
            assert mock_catalog.put.call_count == 5

            
class TestGetKeyValues:
    """Test suite for the get_key_values utility function."""

    def test_get_key_values_single_key(self):
        row = {"RID": 12345, "Name": "Sample A"}
        assert get_key_values(row, ["RID"]) == 12345
        assert get_key_values(row, ["Name"]) == "Sample A"

    def test_get_key_values_multiple_keys(self):
        row = {"RID": 12345, "Project": "P1", "Subject": "S1"}
        assert get_key_values(row, ["Project", "Subject"]) == ("P1", "S1")

    def test_get_key_values_empty_keys(self):
        row = {"RID": 12345}
        # Updated to check for the new ValueError
        with pytest.raises(ValueError, match="a list of key column names are needed"):
            get_key_values(row, [])

    def test_get_key_values_missing_key(self):
        row = {"RID": 12345}
        with pytest.raises(KeyError, match="MissingCol"):
            get_key_values(row, ["MissingCol"])

class TestErmrestDeleteFunctions:

    @pytest.fixture
    def mock_catalog(self):
        """Provides a mocked ERMrest catalog object with a dummy delete method."""
        catalog = MagicMock()
        catalog.delete.return_value.status_code = 200
        catalog.delete.return_value.headers = {}
        return catalog

    # --- Tests for get_batch_size_by_str_length ---

    def test_batch_size_single_key(self):
        keys = ['id']
        kvals = [1, 2, 3, 4, 5]
        
        # Math breakdown for your single key logic:
        # kcnames_length = len(urlquote("id")) = 2
        # Base len: kcnames_length + len('any()') = 2 + 5 = 7
        # index 0: '1' -> len("1") + 1 = 2 -> total length = 9
        # index 1: '2' -> len("2") + 1 = 2 -> total length = 11
        # index 2: '3' -> len("3") + 1 = 2 -> total length = 13
        
        # Limit 10 breaks at index 1 (11 >= 10), so only index 0 fits (batch size 1)
        assert get_batch_size_by_str_length(keys, kvals, 0, length_limit=10) == 1
        
        # Limit 12 breaks at index 2 (13 >= 12), so indices 0 and 1 fit (batch size 2)
        assert get_batch_size_by_str_length(keys, kvals, 0, length_limit=12) == 2

    def test_batch_size_forces_minimum_one(self):
        keys = ['id']
        kvals = ["a_very_long_string_value"]
        # Even if the single value causes the length to exceed the limit immediately, 
        # your fail-safe should force a batch size of 1.
        assert get_batch_size_by_str_length(keys, kvals, 0, length_limit=5) == 1

    def test_batch_size_multi_key(self):
        keys = ['id1', 'id2']
        kvals = [(1, 2), (3, 4), (5, 6)]
        # Given a generous limit, multiple items should be batched together
        assert get_batch_size_by_str_length(keys, kvals, 0, length_limit=100) > 1

    # --- Tests for delete_table_rows ---

    def test_delete_rows_missing_args(self, mock_catalog):
        with pytest.raises(ValueError, match="DELETE ERROR: delete_table_rows requires either constraints"):
            delete_table_rows(mock_catalog, "schema", "table")

    def test_delete_rows_dry_run(self, mock_catalog):
        delete_table_rows(mock_catalog, "s", "t", key="id", values=[1, 2], dry_run=True)
        # Verify the catalog's delete method is bypassed completely
        mock_catalog.delete.assert_not_called()

    def test_delete_rows_live_run(self, mock_catalog):
        delete_table_rows(mock_catalog, "s", "t", key="id", values=[1, 2], dry_run=False)
        mock_catalog.delete.assert_called_once_with("/entity/M:=s:t/id=ANY(1,2)")

    def test_delete_rows_url_encoding(self, mock_catalog):
        # Using spaces and special chars to verify urlquote applies correctly
        delete_table_rows(mock_catalog, "schema 1", "table/1", key="id&key", values=["v 1"], dry_run=False)
        mock_catalog.delete.assert_called_once_with("/entity/M:=schema%201:table%2F1/id%26key=ANY(v%201)")

    def test_delete_rows_404_handling(self, mock_catalog):
        # Simulate a 404 Not Found error from requests
        mock_404_resp = MagicMock()
        mock_404_resp.status_code = 404
        mock_catalog.delete.side_effect = requests.HTTPError(response=mock_404_resp)
        
        # This should NOT raise an exception (it catches and logs it instead)
        delete_table_rows(mock_catalog, "s", "t", key="id", values=[1], dry_run=False)

    def test_delete_rows_500_handling(self, mock_catalog):
        # Simulate a 500 Server Error
        mock_500_resp = MagicMock()
        mock_500_resp.status_code = 500
        mock_catalog.delete.side_effect = requests.HTTPError(response=mock_500_resp)
        
        # This SHOULD raise the exception for non-404 errors
        with pytest.raises(requests.HTTPError):
            delete_table_rows(mock_catalog, "s", "t", key="id", values=[1], dry_run=False)

    # --- Tests for delete_table_rows_by_keys ---

    def test_orchestrator_early_exit(self, mock_catalog):
        # Returns silently without acting if key_values is empty
        assert delete_table_rows_by_keys(mock_catalog, "s", "t", ["id"], []) is None

    def test_orchestrator_length_mismatch(self, mock_catalog):
        with pytest.raises(ValueError, match="INPUT_ERROR: len of key"):
            # 2 keys specified, but only 1 value per tuple provided
            delete_table_rows_by_keys(mock_catalog, "s", "t", ["id1", "id2"], [(1,)])

    def test_orchestrator_batching_execution(self, mock_catalog):
        keys = ['id']
        kvals = [1, 2, 3, 4]
        # Using a limit of 10 forces the function to process a batch size of 1 per loop
        limit = 10 
        
        # Patch the lower-level function (referenced correctly relative to utils.data)
        with patch("deriva.utils.extras.data.delete_table_rows") as mock_delete:
            delete_table_rows_by_keys(mock_catalog, "s", "t", keys, kvals, length_limit=limit, dry_run=True)
            # Since size=4 and batch=1, it should loop and call delete_table_rows 4 times
            assert mock_delete.call_count == 4

    def test_orchestrator_multi_key_formatting(self, mock_catalog):
        keys = ['id1', 'id2']
        kvals = [(1, 'a'), (2, 'b')]
        
        with patch("deriva.utils.extras.data.delete_table_rows") as mock_delete:
            # Omit length_limit so it falls back to URL_LENGTH_LIMIT (plenty big)
            delete_table_rows_by_keys(mock_catalog, "s", "t", keys, kvals, length_limit=2000, dry_run=False)
            
            # Should batch both into 1 call
            mock_delete.assert_called_once()
            
            # Verify the multi-key constraint formatting logic built inside the orchestrator
            called_kwargs = mock_delete.call_args.kwargs
            assert called_kwargs['constraints'] == "id1=1&id2=a;id1=2&id2=b"
            
