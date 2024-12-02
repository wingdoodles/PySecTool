from volatility3.framework import contexts, automagic, interfaces
from volatility3.plugins.windows import pslist, netscan, cmdline

class ForensicsAnalyzer:
    def analyze_memory(self, dump_path):
        # Create analysis context
        context = contexts.Context()
        context.config['automagic.LayerStacker.single_location'] = dump_path
        
        # Initialize automagic
        available_automagics = automagic.available(context)
        
        results = []
        plugins = [
            pslist.PsList,    # Process listing
            netscan.NetScan,  # Network connections
            cmdline.CmdLine   # Command line arguments
        ]
        
        for plugin in plugins:
            try:
                constructed = plugin(context, None)
                treegrid = constructed.run()
                results.append({
                    'plugin': plugin.__name__,
                    'data': self._parse_results(treegrid)
                })
            except Exception as e:
                results.append({
                    'plugin': plugin.__name__,
                    'error': str(e)
                })
                
        return results
        
    def _parse_results(self, treegrid):
        return [row._asdict() for row in treegrid]        