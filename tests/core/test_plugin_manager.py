"""
Tests for the core Plugin Manager.
"""

import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer

# Ensure src is in path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from src.sniper.core.plugin_manager import PluginInterface, PluginManager

# --- Test Plugin Implementations ---


class MockPluginGood(PluginInterface):
    name = "GoodPlugin"
    description = "A plugin that loads and unloads successfully."
    load_called = False
    unload_called = False
    register_cli_called = False

    def load(self) -> bool:
        self.load_called = True
        return True

    def unload(self) -> bool:
        self.unload_called = True
        return True

    def register_cli_commands(self, cli_app):
        self.register_cli_called = True

        # Example: Add a dummy command
        @cli_app.command(self.name.lower())
        def _dummy_command():
            pass


class MockPluginBadLoad(PluginInterface):
    name = "BadLoadPlugin"
    description = "A plugin that fails to load."
    load_called = False
    unload_called = False

    def load(self) -> bool:
        self.load_called = True
        return False  # Simulate load failure

    def unload(self) -> bool:
        # Should ideally not be called if load failed, but test anyway
        self.unload_called = True
        return True


class MockPluginBadUnload(PluginInterface):
    name = "BadUnloadPlugin"
    description = "A plugin that loads but fails to unload."
    load_called = False
    unload_called = False

    def load(self) -> bool:
        self.load_called = True
        return True

    def unload(self) -> bool:
        self.unload_called = True
        return False  # Simulate unload failure


class MockPluginLoadError(PluginInterface):
    name = "LoadErrorPlugin"
    description = "A plugin that raises an error during load."

    def load(self) -> bool:
        raise RuntimeError("Simulated load error")

    def unload(self) -> bool:
        return True


class MockPluginUnloadError(PluginInterface):
    name = "UnloadErrorPlugin"
    description = "A plugin that raises an error during unload."

    def load(self) -> bool:
        return True  # Load succeeds

    def unload(self) -> bool:
        raise RuntimeError("Simulated unload error")


# Add a plugin with a duplicate name
class MockPluginGoodDuplicate(PluginInterface):
    name = "GoodPlugin"  # Same name as MockPluginGood
    description = "A duplicate plugin."

    def load(self) -> bool:
        return True

    def unload(self) -> bool:
        return True


# --- Fixtures ---


@pytest.fixture
def temp_plugin_dir(tmp_path):
    """Create a temporary directory structure for plugins."""
    plugins_root = tmp_path / "temp_plugins"
    plugins_root.mkdir()

    # Plugin 1: Good Plugin
    good_plugin_dir = plugins_root / "good"
    good_plugin_dir.mkdir()
    good_plugin_file = good_plugin_dir / "good_plugin.py"
    good_plugin_file.write_text(
        """
from src.sniper.core.plugin_manager import PluginInterface

class MockPluginGood(PluginInterface):
    name = "GoodPlugin"
    description = "A plugin that loads and unloads successfully."
    load_called = False
    unload_called = False
    register_cli_called = False

    def load(self) -> bool:
        self.load_called = True
        print(f"LOAD CALLED for {self.name}")
        return True

    def unload(self) -> bool:
        self.unload_called = True
        print(f"UNLOAD CALLED for {self.name}")
        return True

    def register_cli_commands(self, cli_app):
        self.register_cli_called = True
        print(f"REGISTER CLI CALLED for {self.name}")
        @cli_app.command(self.name.lower())
        def _dummy_command():
            pass
"""
    )
    (good_plugin_dir / "__init__.py").touch()

    # Plugin 2: Bad Load Plugin
    badload_plugin_dir = plugins_root / "badload"
    badload_plugin_dir.mkdir()
    badload_plugin_file = badload_plugin_dir / "badload_plugin.py"
    badload_plugin_file.write_text(
        """
from src.sniper.core.plugin_manager import PluginInterface

class MockPluginBadLoad(PluginInterface):
    name = "BadLoadPlugin"
    description = "A plugin that fails to load."
    load_called = False
    unload_called = False

    def load(self) -> bool:
        self.load_called = True
        print(f"LOAD CALLED for {self.name}")
        return False

    def unload(self) -> bool:
        self.unload_called = True
        print(f"UNLOAD CALLED for {self.name}")
        return True
"""
    )
    (badload_plugin_dir / "__init__.py").touch()

    # Plugin 3: Load Error Plugin
    loaderror_plugin_dir = plugins_root / "loaderror"
    loaderror_plugin_dir.mkdir()
    loaderror_plugin_file = loaderror_plugin_dir / "loaderror_plugin.py"
    loaderror_plugin_file.write_text(
        """
from src.sniper.core.plugin_manager import PluginInterface

class MockPluginLoadError(PluginInterface):
    name = "LoadErrorPlugin"
    description = "A plugin that raises an error during load."

    def load(self) -> bool:
        print(f"LOAD CALLED for {self.name}")
        raise RuntimeError(\"Simulated load error\")

    def unload(self) -> bool:
        print(f"UNLOAD CALLED for {self.name}")
        return True
"""
    )
    (loaderror_plugin_dir / "__init__.py").touch()

    # Plugin 4: Bad Unload Plugin
    badunload_plugin_dir = plugins_root / "badunload"
    badunload_plugin_dir.mkdir()
    badunload_plugin_file = badunload_plugin_dir / "badunload_plugin.py"
    badunload_plugin_file.write_text(
        """
from src.sniper.core.plugin_manager import PluginInterface

class MockPluginBadUnload(PluginInterface):
    name = "BadUnloadPlugin"
    description = "A plugin that loads but fails to unload."
    load_called = False
    unload_called = False

    def load(self) -> bool:
        self.load_called = True
        print(f"LOAD CALLED for {self.name}")
        return True

    def unload(self) -> bool:
        self.unload_called = True
        print(f"UNLOAD CALLED for {self.name}")
        return False # Simulate unload failure
"""
    )
    (badunload_plugin_dir / "__init__.py").touch()

    # Plugin 5: Unload Error Plugin
    unloaderror_plugin_dir = plugins_root / "unloaderror"
    unloaderror_plugin_dir.mkdir()
    unloaderror_plugin_file = unloaderror_plugin_dir / "unloaderror_plugin.py"
    unloaderror_plugin_file.write_text(
        """
from src.sniper.core.plugin_manager import PluginInterface

class MockPluginUnloadError(PluginInterface):
    name = "UnloadErrorPlugin"
    description = "A plugin that raises an error during unload."

    def load(self) -> bool:
        print(f"LOAD CALLED for {self.name}")
        return True

    def unload(self) -> bool:
        print(f"UNLOAD CALLED for {self.name}")
        raise RuntimeError(\"Simulated unload error\")
"""
    )
    (unloaderror_plugin_dir / "__init__.py").touch()

    # Add directory to sys.path to allow imports
    sys.path.insert(0, str(tmp_path))
    yield str(plugins_root)
    # Clean up sys.path
    sys.path.pop(0)


@pytest.fixture
def temp_plugin_dir_with_duplicates(tmp_path):
    """Create a temporary directory structure including duplicate plugin names."""
    plugins_root = tmp_path / "temp_plugins_dupe"
    plugins_root.mkdir()

    # Plugin 1: Good Plugin
    good_plugin_dir = plugins_root / "good"
    good_plugin_dir.mkdir()
    good_plugin_file = good_plugin_dir / "good_plugin.py"
    good_plugin_file.write_text(
        """
from src.sniper.core.plugin_manager import PluginInterface
class MockPluginGood(PluginInterface):
    name = "GoodPlugin"
    description = "Good Plugin 1"
    def load(self): return True
    def unload(self): return True
"""
    )
    (good_plugin_dir / "__init__.py").touch()

    # Plugin 2: Another plugin with the SAME name
    dupe_plugin_dir = plugins_root / "dupe"
    dupe_plugin_dir.mkdir()
    dupe_plugin_file = dupe_plugin_dir / "dupe_plugin.py"
    dupe_plugin_file.write_text(
        """
from src.sniper.core.plugin_manager import PluginInterface
class MockPluginGoodDuplicate(PluginInterface):
    name = "GoodPlugin" # Duplicate Name
    description = "Good Plugin 2 (Duplicate)"
    def load(self): return True
    def unload(self): return True
"""
    )
    (dupe_plugin_dir / "__init__.py").touch()

    # Add directory to sys.path to allow imports
    sys.path.insert(0, str(tmp_path))
    yield str(plugins_root)
    # Clean up sys.path
    sys.path.pop(0)


# --- Test Cases ---


class TestPluginManagerInit:
    """Tests for PluginManager.__init__"""

    def test_init_default(self):
        """Test initialization with default arguments."""
        pm = PluginManager()
        assert pm.plugin_dirs == ["src/sniper/plugins"]
        assert pm.plugins == {}
        assert pm.loaded_plugins == {}
        assert pm._discovered_plugin_classes == {}


def test_discover_plugins(temp_plugin_dir):
    """Test plugin discovery from a temporary directory."""
    manager = PluginManager(plugin_dirs=[temp_plugin_dir])
    manager.discover_plugins()

    assert len(manager._discovered_plugin_classes) == 5
    assert "GoodPlugin" in manager._discovered_plugin_classes
    assert "BadLoadPlugin" in manager._discovered_plugin_classes
    assert "LoadErrorPlugin" in manager._discovered_plugin_classes
    assert "BadUnloadPlugin" in manager._discovered_plugin_classes
    assert "UnloadErrorPlugin" in manager._discovered_plugin_classes
    assert issubclass(manager._discovered_plugin_classes["GoodPlugin"], PluginInterface)


def test_discover_plugins_nonexistent_dir(caplog):
    """Test discovery with a non-existent directory."""
    manager = PluginManager(plugin_dirs=["nonexistent/path"])
    with caplog.at_level(logging.WARNING):
        manager.discover_plugins()
    assert (
        "Plugin directory not found or not a directory: nonexistent/path" in caplog.text
    )
    assert len(manager._discovered_plugin_classes) == 0


def test_instantiate_and_load_plugin_success(temp_plugin_dir):
    """Test instantiating and loading a valid plugin."""
    manager = PluginManager(plugin_dirs=[temp_plugin_dir])
    manager.discover_plugins()

    # Instantiate first
    instance = manager.instantiate_plugin("GoodPlugin")
    assert instance is not None
    assert instance.name == "GoodPlugin"
    assert "GoodPlugin" in manager.plugins
    assert instance.load_called is False  # Load not called yet

    # Load
    success = manager.load_plugin("GoodPlugin")
    assert success is True
    assert "GoodPlugin" in manager.loaded_plugins
    # Accessing the instance directly from the manager dict
    assert manager.plugins["GoodPlugin"].load_called is True


def test_load_plugin_directly(temp_plugin_dir):
    """Test loading a plugin without prior instantiation call."""
    manager = PluginManager(plugin_dirs=[temp_plugin_dir])
    manager.discover_plugins()

    success = manager.load_plugin("GoodPlugin")
    assert success is True
    assert "GoodPlugin" in manager.plugins
    assert "GoodPlugin" in manager.loaded_plugins
    assert manager.plugins["GoodPlugin"].load_called is True


def test_load_plugin_already_loaded(temp_plugin_dir, caplog):
    """Test loading a plugin that is already loaded."""
    manager = PluginManager(plugin_dirs=[temp_plugin_dir])
    manager.discover_plugins()
    manager.load_plugin("GoodPlugin")  # First load

    with caplog.at_level(logging.WARNING):
        success = manager.load_plugin("GoodPlugin")  # Second load

    assert success is True
    assert "Plugin 'GoodPlugin' already loaded." in caplog.text
    # Ensure load was not called again (assuming load_called is reset on init)
    # This requires checking the instance attribute state. Let's get the instance.
    instance = manager.loaded_plugins["GoodPlugin"]
    # We need to ensure load_called was only set once
    # Re-instantiating test classes for isolated state might be better
    # For now, assert based on the log message confirming it wasn't re-loaded.


def test_load_plugin_load_returns_false(temp_plugin_dir, caplog):
    """Test loading a plugin whose load() method returns False."""
    manager = PluginManager(plugin_dirs=[temp_plugin_dir])
    manager.discover_plugins()

    with caplog.at_level(logging.ERROR):
        success = manager.load_plugin("BadLoadPlugin")

    assert success is False
    assert "BadLoadPlugin" not in manager.loaded_plugins
    assert "BadLoadPlugin" not in manager.plugins  # Should be removed if load fails
    assert "Plugin 'BadLoadPlugin' load() method returned False." in caplog.text
    # Check if the instance's load method was called
    # This requires inspecting the class from the discovery phase or complex mocking
    # For now, rely on the log message and return status.


def test_load_plugin_load_raises_error(temp_plugin_dir, caplog):
    """Test loading a plugin whose load() method raises an exception."""
    manager = PluginManager(plugin_dirs=[temp_plugin_dir])
    manager.discover_plugins()

    with caplog.at_level(logging.ERROR):
        success = manager.load_plugin("LoadErrorPlugin")

    assert success is False
    assert "LoadErrorPlugin" not in manager.loaded_plugins
    assert "LoadErrorPlugin" not in manager.plugins  # Should be removed
    assert "Error loading plugin 'LoadErrorPlugin': Simulated load error" in caplog.text


def test_unload_plugin_success(temp_plugin_dir):
    """Test unloading a successfully loaded plugin."""
    manager = PluginManager(plugin_dirs=[temp_plugin_dir])
    manager.discover_plugins()
    manager.load_plugin("GoodPlugin")
    instance = manager.loaded_plugins["GoodPlugin"]

    assert "GoodPlugin" in manager.loaded_plugins
    assert "GoodPlugin" in manager.plugins

    success = manager.unload_plugin("GoodPlugin")
    assert success is True
    assert "GoodPlugin" not in manager.loaded_plugins
    assert "GoodPlugin" not in manager.plugins  # Check it was removed
    assert instance.unload_called is True


def test_unload_plugin_not_loaded(temp_plugin_dir, caplog):
    """Test unloading a plugin that isn't loaded."""
    manager = PluginManager(plugin_dirs=[temp_plugin_dir])
    manager.discover_plugins()
    # Instantiate but don't load
    manager.instantiate_plugin("GoodPlugin")

    with caplog.at_level(logging.DEBUG):
        success = manager.unload_plugin("GoodPlugin")

    assert success is True  # Should not fail
    assert "Plugin 'GoodPlugin' not loaded or already unloaded." in caplog.text
    assert "GoodPlugin" not in manager.loaded_plugins


def test_unload_plugin_unload_returns_false(temp_plugin_dir, caplog):
    """Test unloading a plugin whose unload() returns False."""
    manager = PluginManager(plugin_dirs=[temp_plugin_dir])
    manager.discover_plugins()
    manager.load_plugin("BadUnloadPlugin")  # Load the new plugin

    assert "BadUnloadPlugin" in manager.loaded_plugins

    with caplog.at_level(logging.ERROR):
        success = manager.unload_plugin("BadUnloadPlugin")

    assert success is False
    assert (
        "BadUnloadPlugin" in manager.loaded_plugins
    )  # Should remain loaded if unload fails
    assert "Plugin 'BadUnloadPlugin' unload() method returned False." in caplog.text


def test_unload_plugin_unload_raises_error(temp_plugin_dir, caplog):
    """Test unloading a plugin whose unload() raises an error."""
    manager = PluginManager(plugin_dirs=[temp_plugin_dir])
    manager.discover_plugins()
    manager.load_plugin("UnloadErrorPlugin")  # Load the new plugin

    assert "UnloadErrorPlugin" in manager.loaded_plugins

    with caplog.at_level(logging.ERROR):
        success = manager.unload_plugin("UnloadErrorPlugin")

    assert success is False
    assert "UnloadErrorPlugin" in manager.loaded_plugins  # Should remain loaded
    assert (
        "Error unloading plugin 'UnloadErrorPlugin': Simulated unload error"
        in caplog.text
    )


def test_load_all_plugins(temp_plugin_dir, caplog):
    """Test loading all discovered plugins."""
    manager = PluginManager(plugin_dirs=[temp_plugin_dir])
    with caplog.at_level(logging.INFO):
        manager.load_all_plugins()

    assert (
        len(manager.loaded_plugins) == 3
    )  # Good, BadUnload, UnloadError should load initially
    assert "GoodPlugin" in manager.loaded_plugins
    assert "BadUnloadPlugin" in manager.loaded_plugins
    assert "UnloadErrorPlugin" in manager.loaded_plugins
    assert "BadLoadPlugin" not in manager.loaded_plugins  # Failed load()
    assert "LoadErrorPlugin" not in manager.loaded_plugins  # Raised error on load()
    assert "Loaded 3 out of 5 discovered plugins." in caplog.text


def test_unload_all_plugins(temp_plugin_dir, caplog):
    """Test unloading all loaded plugins."""
    manager = PluginManager(plugin_dirs=[temp_plugin_dir])
    manager.load_all_plugins()  # Loads GoodPlugin, BadUnloadPlugin, UnloadErrorPlugin
    good_instance = manager.loaded_plugins["GoodPlugin"]

    assert len(manager.loaded_plugins) == 3  # Verify initial loaded count

    with caplog.at_level(logging.INFO):
        manager.unload_all_plugins()

    assert len(manager.loaded_plugins) == 2  # Check that 2 failed to unload
    assert "GoodPlugin" not in manager.loaded_plugins  # Should be unloaded
    assert "BadUnloadPlugin" in manager.loaded_plugins  # Failed unload (returns False)
    assert "UnloadErrorPlugin" in manager.loaded_plugins  # Failed unload (raises Error)
    assert good_instance.unload_called is True
    # Check the log message for the number successfully unloaded
    assert "Unloaded 1 plugins successfully." in caplog.text


def test_register_all_cli_commands(temp_plugin_dir):
    """Test registering CLI commands from loaded plugins."""
    manager = PluginManager(plugin_dirs=[temp_plugin_dir])
    manager.load_all_plugins()  # Loads GoodPlugin
    instance = manager.loaded_plugins["GoodPlugin"]

    mock_app = MagicMock(spec=typer.Typer)
    manager.register_all_cli_commands(mock_app)

    # Check if the instance method was called
    assert instance.register_cli_called is True
    # Check if Typer app's add_command (or similar) was called by the mock plugin
    # This depends on the mock plugin's implementation.
    # In our MockPluginGood, it calls `cli_app.command(self.name.lower())`
    # which translates to `mock_app.command('goodplugin')`
    # We need to check if the 'command' method was called on the mock_app.
    mock_app.command.assert_called_with("goodplugin")


def test_discover_plugins_duplicate_name(temp_plugin_dir_with_duplicates, caplog):
    """Test plugin discovery handles duplicate names (logs warning, keeps last)."""
    manager = PluginManager(plugin_dirs=[temp_plugin_dir_with_duplicates])
    with caplog.at_level(logging.WARNING):
        manager.discover_plugins()

    assert (
        len(manager._discovered_plugin_classes) == 1
    )  # Only one entry for "GoodPlugin"
    assert "GoodPlugin" in manager._discovered_plugin_classes

    # Check that the warning was logged - partial match since exact message includes paths
    assert "Duplicate plugin name 'GoodPlugin' found in" in caplog.text

    # Check that the *last* discovered plugin instance is kept (based on dir iteration order)
    # This assertion is removed as os.listdir order is not guaranteed.
    # kept_plugin_class = manager._discovered_plugin_classes["GoodPlugin"]
    # assert kept_plugin_class.description == "Good Plugin 2 (Duplicate)"


def test_plugin_manager_plugin_dir_resolution():
    """Test that the PluginManager can handle relative and absolute paths."""
    # Test with relative path
    relative_manager = PluginManager(plugin_dirs=["tests/fixtures/plugins"])
    assert len(relative_manager.plugin_dirs) == 1
    assert relative_manager.plugin_dirs[0] == "tests/fixtures/plugins"

    # Test with absolute path
    project_root = Path(os.getcwd())
    abs_path = str(project_root / "tests" / "fixtures" / "plugins")
    abs_manager = PluginManager(plugin_dirs=[abs_path])
    assert len(abs_manager.plugin_dirs) == 1
    assert abs_manager.plugin_dirs[0] == abs_path

    # Test with default path - allow for either app/plugins or src/sniper/plugins
    default_manager = PluginManager()
    assert len(default_manager.plugin_dirs) == 1
    assert default_manager.plugin_dirs[0] in ["app/plugins", "src/sniper/plugins"]


# TODO: Add tests for discovery from multiple directories
# TODO: Add tests for plugins in __init__.py vs dedicated files
# TODO: Refactor fixture to inject test classes directly instead of writing files?
