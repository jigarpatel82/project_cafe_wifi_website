 $(function() {
// setTimeout() function will be fired after page is loaded
// it will wait for 5 sec. and then will fire
// $(".message_flash").hide() function
  setTimeout(function() {
      $(".message_flash").hide('blind', {}, 500)
  }, 5000);
})