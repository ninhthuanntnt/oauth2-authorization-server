package com.ntnt.microservices.oauth2.authorization.server.jackson;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import org.springframework.security.core.GrantedAuthority;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class ImmutableListDeserializer extends JsonDeserializer<List<? extends GrantedAuthority>> {

  @Override
  public List<? extends GrantedAuthority> deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException, JsonProcessingException {
    ObjectMapper mapper = (ObjectMapper) jp.getCodec();
    JsonNode node = mapper.readTree(jp);
    List<GrantedAuthority> resultList = new ArrayList<>();
    if (node!=null) {
      if (node instanceof ArrayNode arrayNode) {
        for (JsonNode elementNode : arrayNode) {
          resultList.add(mapper.readValue(elementNode.traverse(mapper), GrantedAuthority.class));
        }
      } else {
        resultList.add(mapper.readValue(node.traverse(mapper), GrantedAuthority.class));
      }
    }
    return List.copyOf(resultList);
  }
}