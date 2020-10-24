import org.apache.jena.query.Dataset;
import org.apache.jena.query.DatasetFactory;
import org.apache.jena.query.Query;
import org.apache.jena.query.QueryExecution;
import org.apache.jena.query.QueryExecutionFactory;
import org.apache.jena.query.QueryFactory;
import org.apache.jena.query.QuerySolution;
import org.apache.jena.query.ResultSet;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.util.FileManager;

public class CyberSecurity {
	

	public static void main(String[] args) {
		Model model = ModelFactory.createDefaultModel();
		model = FileManager.get().loadModel("csa_ontology.owl");
		Dataset data = DatasetFactory.create(model);

		try{
			//query1(data);
			//query2(data);
			query3(data);
		}finally{
			model.close();
			data.close();
		}
	}
	
	public static void query1(Dataset dataset){
		String queryText1 = "PREFIX cst: <http://www.semanticweb.org/desia/ontologies/2020/0/untitled-ontology-5#>\r\n" + 
				"SELECT ?Tools ?Vulnerability\r\n" + 
				"WHERE { ?Tools cst:exploits ?Vulnerability }";
		
		Query query = QueryFactory.create(queryText1);
		QueryExecution queryexec = QueryExecutionFactory.create(query, dataset);
		
		try{
			ResultSet results = queryexec.execSelect();
			while(results.hasNext()){
				QuerySolution solution = results.nextSolution();
				Resource tools = solution.getResource("Tools");
				Resource vuln = solution.getResource("Vulnerability");
				System.out.println(tools);
				System.out.println(vuln);
			}
		}finally{
			queryexec.close();
			dataset.close();
		}
	}
	
	public static void query2(Dataset dataset){
		String queryText2 = "PREFIX cst: <http://www.semanticweb.org/desia/ontologies/2020/0/untitled-ontology-5#>\r\n" + 
				"SELECT ?Tools ?Vulnerability ?Action ?Target ?UnauthorizedResult\r\n" + 
				"WHERE { ?Tools cst:exploits ?Vulnerability.\r\n" + 
				"	                ?Vulnerability cst:toProduce ?Action.\r\n" + 
				"	                ?Action cst:executedOn ?Target.\r\n" + 
				"	                ?Target cst:toAchive ?UnauthorizedResult." + 
				"					?UnauthorizedResult cst:hasDamageCost 1.0E7}";
		
		Query query = QueryFactory.create(queryText2);
		QueryExecution queryexec = QueryExecutionFactory.create(query, dataset);
		
		try{
			ResultSet results = queryexec.execSelect();
			while(results.hasNext()){
				QuerySolution solution = results.nextSolution();
				Resource tools = solution.getResource("Tools");
				Resource vuln = solution.getResource("Vulnerability");
				Resource action = solution.getResource("Action");
				Resource target = solution.getResource("Target");
				Resource unauthResult = solution.getResource("UnauthorizedResult");
				System.out.println(tools);
				System.out.println(vuln);
				System.out.println(action);
				System.out.println(target);
				System.out.println(unauthResult);
			}
		}finally{
			queryexec.close();
			dataset.close();
		}
	}
	
	public static void query3(Dataset dataset){
		String queryText3 = "PREFIX cst: <http://www.semanticweb.org/desia/ontologies/2020/0/untitled-ontology-5#>\r\n" + 
				"				SELECT ?Vulnerability ?Action \r\n" + 
				"				WHERE { ?Vulnerability cst:toProduce ?Action}";
		
		Query query = QueryFactory.create(queryText3);
		QueryExecution queryexec = QueryExecutionFactory.create(query, dataset);
		
		try{
			ResultSet results = queryexec.execSelect();
			while(results.hasNext()){
				QuerySolution solution = results.nextSolution();
				Resource vuln = solution.getResource("Vulnerability");
				Resource action = solution.getResource("Action");
				System.out.println(vuln);
				System.out.println(action);

			}
		}finally{
			queryexec.close();
			dataset.close();
		}
}
}
