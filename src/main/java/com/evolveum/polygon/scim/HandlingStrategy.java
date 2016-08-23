package com.evolveum.polygon.scim;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.message.BasicHeader;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ObjectClassInfoBuilder;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.ContainsAllValuesFilter;
import org.json.JSONObject;

public interface HandlingStrategy {

	Header PRETTYPRINTHEADER = new BasicHeader("X-PrettyPrint", "1");

	public ConnectorObject buildConnectorObject(JSONObject resourceJsonObject, String resourceEndPoint)
			throws ConnectorException;

	public Uid specialGroupUpdateProcedure(HttpResponse response, JSONObject jsonObject, String uri, Header authHeader,
			CrudManagerScim manager);

	public Uid createEntity(String resourceEndPoint, ObjectTranslator objectTranslator, Set<Attribute> attributes,
			HashSet<Attribute> injectedAttributeSet);

	public StringBuilder visitContainsAllValuesFilter(String p, ContainsAllValuesFilter filter);

	public Map<String, Map<String, Object>> parseAttribute(JSONObject attribute,
			Map<String, Map<String, Object>> attributeMap, ParserSchemaScim parser);

	public ObjectClassInfoBuilder schemaBuilderProcedure(String attributeName,
			Map<String, Map<String, Object>> attributeMap, ObjectClassInfoBuilder builder,
			SchemaObjectBuilderGeneric schemaBuilder);

	public List<Map<String, Map<String, Object>>> getAttributeMapList(
			List<Map<String, Map<String, Object>>> attributeMapList);
}
