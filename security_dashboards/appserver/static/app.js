require([
    'jquery',
    'https://cdnjs.cloudflare.com/ajax/libs/markdown-it/12.1.0/markdown-it.min.js',
    'splunkjs/mvc/simplexml/ready!'
], function($){
    console.log("HERE");
    var MarkdownIt = require("https://cdnjs.cloudflare.com/ajax/libs/markdown-it/12.1.0/markdown-it.min.js"), md = new MarkdownIt();
    var result = md.render($('#content').text());
    console.log(result);
    $("#content").html(result);
});