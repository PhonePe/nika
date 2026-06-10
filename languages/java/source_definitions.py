JAVA_SOURCE_DEFINITIONS = {
    "remote_input": [
        # Spring MVC / WebFlux controllers
        "@RequestMapping",
        "@GetMapping",
        "@PostMapping",
        "@PutMapping",
        "@DeleteMapping",
        "@PatchMapping",
        # JAX-RS resources
        "@Path",
        # Spring WebSocket / STOMP message handlers
        "@MessageMapping",
        "@SubscribeMapping",
        # Spring for GraphQL controllers
        "@QueryMapping",
        "@MutationMapping",
        "@SubscriptionMapping",
        "@SchemaMapping",
        "@BatchMapping",
        # Netflix DGS GraphQL handlers
        "@DgsQuery",
        "@DgsMutation",
        "@DgsSubscription",
        "@DgsData",
    ],
    "message_payload": [
        "@KafkaListener",
        "@RabbitListener",
        "@SqsListener",
        "@JmsListener",
        "@StreamListener",
    ],
}
