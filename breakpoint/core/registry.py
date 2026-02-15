from typing import Dict, Type, List, Optional, Any
from .attack import Attack

class AttackRegistry:
    """
    Central repository for all available attack modules.
    Enables dynamic loading, filtering, and execution of attacks.
    Phase 1: Simple registry.
    Phase 2: Plugin loader from external paths.
    """
    _registry: Dict[str, Type[Attack]] = {}

    @classmethod
    def register(cls, attack_cls: Type[Attack]):
        """Decorator or direct method to register an attack class."""
        attack_name = attack_cls.name
        if isinstance(attack_name, property):
            # Instantiate to access prop if needed, or rely on static def.
            # But wait, name is an abstract property. Better to check instance or class attribute.
            pass
        
        # In python, abstract properties on a class are ... tricky without instantiation.
        # We will assume 'name' is also available as a class variable or static method for Registration.
        # Alternatively, we register instance factories.
        
        # Let's simplify: Attack classes should have a static 'NAME' or we instantiate once to get metadata.
        # Examples typically use a class attribute.
        
        # However, following the ABC pattern:
        try:
             # Create a throwaway instance to get metadata if necessary, or introspection.
             # Better pattern: Expect a class attribute 'NAME'.
             pass
        except:
             pass

        cls._registry[attack_cls.__name__] = attack_cls 
        # TODO: Refine key to be the attack ID (e.g., 'sql_injection')

    @classmethod
    def get_attack(cls, name: str) -> Optional[Type[Attack]]:
        return cls._registry.get(name)

    @classmethod
    def list_attacks(cls) -> List[str]:
        return list(cls._registry.keys())

    @classmethod
    def load_modules(cls, package_path: str):
        """
        Dynamically imports all modules in the given package to trigger registration.
        To be implemented in Phase 1.5.
        """
        pass
